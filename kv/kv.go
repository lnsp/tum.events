package kv

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type Credentials struct {
	Token   string
	Project string
}

// Store defines an implementation-agnostic key-value storage interface.
type Store interface {
	AtomicInc(key string) (int64, error)
	Delete(key string) error
	Put(key string, value []byte) error
	Fetch(key string) ([]byte, error)
	List(prefix string) ([]string, []byte, error)
}

func RestoreFromDump(kv Store, reader io.Reader) error {
	kvs := map[string]string{}
	if err := json.NewDecoder(reader).Decode(&kvs); err != nil {
		return err
	}
	for key, value := range kvs {
		if err := kv.Put(key, []byte(value)); err != nil {
			return err
		}
	}
	return nil
}

func WriteToDump(kv Store, writer io.Writer) error {
	keys, _, err := kv.List("")
	if err != nil {
		return err
	}
	kvs := map[string]string{}
	for _, key := range keys {
		value, err := kv.Fetch(key)
		if err != nil {
			return err
		}
		kvs[key] = string(value)
	}
	if err := json.NewEncoder(writer).Encode(kvs); err != nil {
		return err
	}
	return nil
}

var _ Store = (*inMemoryStore)(nil)

type inMemoryStore struct {
	// mu protects the fields below.
	mu  sync.RWMutex
	kvs map[string][]byte
}

// NewInMemoryStore returns a new KV backend using an ephemeral in-memory representation.
func NewInMemoryStore() Store {
	return &inMemoryStore{kvs: make(map[string][]byte)}
}

const inMemoryIntBytes = 8

func (store *inMemoryStore) AtomicInc(key string) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	value := store.kvs[key]
	if len(value) != inMemoryIntBytes {
		value = make([]byte, inMemoryIntBytes)
	}
	next := 1 + int64(binary.LittleEndian.Uint64(value))
	binary.LittleEndian.PutUint64(value, uint64(next))
	store.kvs[key] = value

	return next, nil
}

func (store *inMemoryStore) Delete(key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	delete(store.kvs, key)
	return nil
}

func (store *inMemoryStore) Put(key string, value []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	store.kvs[key] = value[:]
	return nil
}

func (store *inMemoryStore) Fetch(key string) ([]byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	return store.kvs[key], nil
}

func (store *inMemoryStore) List(prefix string) ([]string, []byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	keys := []string{}
	for key := range store.kvs {
		if strings.HasPrefix(string(key), prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	hash := sha1.Sum([]byte(strings.Join(keys, "\x00")))
	return keys, hash[:], nil
}

// NewRemoteStore returns a new storage backend using a managed Valar KV database instance.
func NewRemoteStore(cred Credentials) Store {
	return &remoteStore{&cred, http.DefaultClient}
}

type remoteStore struct {
	*Credentials
	httpClient *http.Client
}

func (store *remoteStore) AtomicInc(key string) (int64, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s?op=inc&mode=atomic", store.Project, key)
	request, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return -1, err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := store.httpClient.Do(request)
	if err != nil {
		return -1, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return -1, err
	}
	num := new(big.Int)
	num.SetBytes(data)
	return num.Int64(), nil
}

func (store *remoteStore) Delete(key string) error {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", store.Project, key)
	request, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := store.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func (store *remoteStore) Put(key string, value []byte) error {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", store.Project, key)
	body := bytes.NewReader(value)
	request, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := store.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func (store *remoteStore) Fetch(key string) ([]byte, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", store.Project, key)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := store.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (store *remoteStore) List(prefix string) ([]string, []byte, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s?mode=list", store.Project, prefix)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := store.httpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	// hash data
	keys := []string{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, nil, err
	}
	hash := sha1.Sum([]byte(strings.Join(keys, "\x00")))
	return keys, hash[:], nil
}
