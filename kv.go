package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

type KVStore struct {
	*KVCreds
}

func (store *KVStore) atomicinc(key string) (int64, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s?op=inc&mode=atomic", store.Project, key)
	request, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return -1, err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := http.DefaultClient.Do(request)
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

func (store *KVStore) delete(key string) error {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", store.Project, key)
	request, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func (store *KVStore) put(key string, value []byte) error {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", store.Project, key)
	body := bytes.NewReader(value)
	request, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func (store *KVStore) fetch(key string) ([]byte, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", store.Project, key)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := http.DefaultClient.Do(request)
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

func (store *KVStore) list(prefix string) ([]string, []byte, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s?mode=list", store.Project, prefix)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+store.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	// hash data
	hash := sha1.Sum(data)
	keys := []string{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, nil, err
	}
	return keys, hash[:], nil
}
