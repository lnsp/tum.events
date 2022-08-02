package structs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lnsp/tumtalks/kv"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

const LoginMaxAttempts = 3

type Login struct {
	Expiration time.Time `json:"e"`
	User       string    `json:"u"`
	Key        string    `json:"k"`
	Code       string    `json:"c"`
	Attempt    int       `json:"a"`
}

func (l *Login) Active() bool {
	return time.Now().Before(l.Expiration) && l.Attempt <= LoginMaxAttempts
}

type Session struct {
	Expiration time.Time `json:"e"`
	User       string    `json:"u"`
	Key        string    `json:"k"`
}

func (s *Session) Active() bool {
	return time.Now().Before(s.Expiration)
}

type Verification struct {
	Expiration time.Time `json:"e"`
	Talk       *Talk     `json:"t"`
}

func (v *Verification) Active() bool {
	return time.Since(v.Expiration) < expirationInterval
}

type Talk struct {
	ID       int64     `json:"i,omitempty"`
	Rank     int64     `json:"-"`
	User     string    `json:"u"`
	Title    string    `json:"t"`
	Category string    `json:"c"`
	Date     time.Time `json:"d"`
	Link     string    `json:"l,omitempty"`
	Body     string    `json:"b,omitempty"`
}

var markdownRenderer = goldmark.New(
	goldmark.WithExtensions(
		extension.NewTypographer(),
		extension.NewLinkify(),
	),
	goldmark.WithParserOptions(
		parser.WithAutoHeadingID(),
	),
	goldmark.WithRendererOptions(
		html.WithHardWraps(),
		html.WithXHTML(),
	),
)
var sanitizePolicy = bluemonday.NewPolicy()

func init() {
	sanitizePolicy.AllowStandardURLs()
	sanitizePolicy.AllowLists()
	sanitizePolicy.AllowElements("h2", "h3", "h4", "h5", "h6", "h7")
	sanitizePolicy.AllowElements("p")
}

func (t *Talk) RenderAsHTML() string {
	var buf bytes.Buffer
	markdownRenderer.Convert([]byte(t.Body), &buf)
	sanitized := sanitizePolicy.SanitizeBytes(buf.Bytes())
	return string(sanitized)
}

type Store struct {
	kv     *kv.Store
	prefix string

	mu       sync.Mutex
	cache    []*Talk
	cachemap map[int64]*Talk
	hash     []byte
}

func NewStore(creds *kv.Credentials, prefix string) *Store {
	return &Store{
		prefix: prefix,
		kv: &kv.Store{
			Credentials: creds,
		},
	}
}

const maxConcurrentLogins = 3
const expirationInterval = 15 * time.Minute
const secretLength = 32

func (store *Store) HasTooManyLogins(user string) (bool, int, error) {
	// List all logins
	loginkeys, _, err := store.kv.List(store.prefix + "_login_")
	if err != nil {
		return false, -1, fmt.Errorf("fetch logins: %w", err)
	}
	// Go through each login and check
	concurrentLogins := 0
	minDelay := -1
	for _, key := range loginkeys {
		data, err := store.kv.Fetch(key)
		if err != nil {
			return false, -1, fmt.Errorf("fetch login: %w", err)
		}
		// Decode login
		var login Login
		if err := json.Unmarshal(data, &login); err != nil {
			return false, -1, fmt.Errorf("decode login: %w", err)
		}
		// Drop verification if expired
		if !login.Active() {
			if err := store.kv.Delete(key); err != nil {
				return false, -1, fmt.Errorf("delete login: %w", err)
			}
			continue
		}
		// Check if we match
		if login.User == user {
			delay := int(time.Until(login.Expiration).Seconds())
			if minDelay == -1 || delay < minDelay {
				minDelay = delay
			}
			concurrentLogins++
		}
	}
	return concurrentLogins >= maxConcurrentLogins, minDelay, nil
}

func (store *Store) HasActiveVerification(user string) (bool, error) {
	// List all verifications
	verifkeys, _, err := store.kv.List(store.prefix + "_verif_")
	if err != nil {
		return false, fmt.Errorf("fetch verifications: %w", err)
	}
	// Go through each verification and check
	for _, key := range verifkeys {
		data, err := store.kv.Fetch(key)
		if err != nil {
			return false, fmt.Errorf("fetch verification: %w", err)
		}
		// Decode verification
		var verification Verification
		if err := json.Unmarshal(data, &verification); err != nil {
			return false, fmt.Errorf("decode verification: %w", err)
		}
		// Drop verification if expired
		if !verification.Active() {
			if err := store.kv.Delete(key); err != nil {
				return false, fmt.Errorf("delete verification: %w", err)
			}
		}
		// Check if we match
		if verification.Talk.User == user {
			return true, nil
		}
	}
	return false, nil
}

func (store *Store) Add(talk *Talk) (string, error) {
	// Generate secret
	randBytes := make([]byte, secretLength)
	rand.Reader.Read(randBytes)
	secret := hex.EncodeToString(randBytes)
	// Get timestamp
	expiration := time.Now().Add(expirationInterval)
	// Create verification
	verif := &Verification{
		Expiration: expiration,
		Talk:       talk,
	}
	key := fmt.Sprintf("%s_verif_%s", store.prefix, secret)
	data, err := json.Marshal(verif)
	if err != nil {
		return "", fmt.Errorf("encode verification: %w", err)
	}
	// Store in KV
	if err := store.kv.Put(key, data); err != nil {
		return "", fmt.Errorf("store verification: %w", err)
	}
	return secret, nil
}

const sessionExpiration = 24 * time.Hour * 30
const loginExpiration = 10 * time.Minute
const loginKeyLen = 32
const loginCodeLen = 6

var ErrLoginInvalidKey = errors.New("invalid key")
var ErrLoginExpired = errors.New("login expired")
var ErrLoginWrongCode = errors.New("wrong code")

func (store *Store) ConfirmLogin(key, code string) (*Session, *Login, error) {
	// Check that key is 32-byte hex string
	if keyBytes, err := hex.DecodeString(key); err != nil || len(keyBytes) != 32 {
		return nil, nil, ErrLoginInvalidKey
	}
	// Fetch login with given key
	loginKey := fmt.Sprintf("%s_login_%s", store.prefix, key)
	data, err := store.kv.Fetch(loginKey)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch login: %w", err)
	}
	var login Login
	if err := json.Unmarshal(data, &login); err != nil {
		return nil, nil, fmt.Errorf("decode login: %w", err)
	}
	// Make sure that login isn't expired
	login.Attempt++
	if !login.Active() {
		// Delete login and say login is expired
		if err := store.kv.Delete(loginKey); err != nil {
			return nil, nil, fmt.Errorf("delete login: %w", err)
		}
		return nil, nil, ErrLoginExpired
	}
	data, err = json.Marshal(login)
	if err != nil {
		return nil, nil, fmt.Errorf("encode login: %w", err)
	}
	if err := store.kv.Put(loginKey, data); err != nil {
		return nil, nil, fmt.Errorf("store login: %w", err)
	}
	// Make sure that code matches
	if login.Code != code {
		return nil, &login, ErrLoginWrongCode
	}
	// Delete login, turn into session
	if err := store.kv.Delete(loginKey); err != nil {
		return nil, nil, fmt.Errorf("delete login: %w", err)
	}
	session := Session{
		Expiration: time.Now().Add(sessionExpiration),
		User:       login.User,
		Key:        login.Key,
	}
	data, err = json.Marshal(&session)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal session: %w", err)
	}
	sessionKey := fmt.Sprintf("%s_session_%s", store.prefix, key)
	if err := store.kv.Put(sessionKey, data); err != nil {
		return nil, nil, fmt.Errorf("store session: %w", err)
	}
	return &session, &login, nil
}

func (store *Store) DeleteSession(key string) error {
	// Check if key with session exists
	if err := store.kv.Delete(fmt.Sprintf("%s_session_%s", store.prefix, key)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (store *Store) VerifySession(key string) (string, error) {
	// Fetch session
	data, err := store.kv.Fetch(fmt.Sprintf("%s_session_%s", store.prefix, key))
	if err != nil {
		return "", fmt.Errorf("fetch session: %w", err)
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return "", fmt.Errorf("decode session: %w", err)
	}
	// Make sure that session is active, else delete
	if !session.Active() {
		if err := store.DeleteSession(key); err != nil {
			return "", err
		}
		return "", nil
	}
	// Return user
	return session.User, nil
}

func (store *Store) AttemptLogin(user string) (*Login, error) {
	// Generate login key
	keyBytes := make([]byte, loginKeyLen)
	rand.Read(keyBytes)
	keyString := hex.EncodeToString(keyBytes)
	// Generate login code
	codeBytes := make([]byte, loginCodeLen)
	rand.Read(codeBytes)
	for i := 0; i < 6; i++ {
		codeBytes[i] = (codeBytes[i] % 10) + '0'
	}
	codeString := string(codeBytes)
	// Create user login attempt and store it
	login := &Login{
		Expiration: time.Now().Add(loginExpiration),
		User:       user,
		Key:        keyString,
		Code:       codeString,
	}
	loginJSON, err := json.Marshal(login)
	if err != nil {
		return nil, fmt.Errorf("marshal login: %w", err)
	}
	// Store in KV
	key := fmt.Sprintf("%s_login_%s", store.prefix, keyString)
	if err := store.kv.Put(key, loginJSON); err != nil {
		return nil, fmt.Errorf("store login: %w", err)
	}
	return login, nil
}

func (store *Store) Verify(secret string) error {
	// Attempt to decode secret and verify length
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		return fmt.Errorf("decode secret: %w", err)
	}
	if len(secretBytes) != secretLength {
		return fmt.Errorf("invalid secret")
	}
	// Retrieve verification and decode
	var verif Verification
	key := fmt.Sprintf("%s_verif_%s", store.prefix, secret)
	verifdata, err := store.kv.Fetch(key)
	if err != nil {
		return fmt.Errorf("fetch verification: %w", err)
	}
	if err := json.Unmarshal(verifdata, &verif); err != nil {
		return fmt.Errorf("decode verification: %w", err)
	}
	// Check expiration time
	if !verif.Active() {
		return fmt.Errorf("verification expired")
	}
	// Delete verification from store
	if err := store.kv.Delete(key); err != nil {
		return fmt.Errorf("delete verification: %w", err)
	}
	return store.InsertTalk(verif.Talk)
}

func (store *Store) DeleteTalk(id int64) error {
	if id == 0 {
		return fmt.Errorf("talk id required")
	}
	talkkey := fmt.Sprintf("%s_talks_%d", store.prefix, id)
	if err := store.kv.Delete(talkkey); err != nil {
		return fmt.Errorf("delete talk: %w", err)
	}

	// Clear cache
	store.mu.Lock()
	defer store.mu.Unlock()

	// Clear hash, drop talk from cache
	store.hash = nil
	delete(store.cachemap, id)
	for i, j := 0, 0; i < len(store.cache); i++ {
		if store.cache[i].ID != id {
			store.cache[j] = store.cache[i]
			j++
		}
	}
	store.cache = store.cache[:len(store.cache)-1]
	return nil
}

func (store *Store) UpdateTalk(talk *Talk) error {
	if talk.ID == 0 {
		return fmt.Errorf("talk id required")
	}
	talkkey := fmt.Sprintf("%s_talks_%d", store.prefix, talk.ID)
	talkdata, err := json.Marshal(talk)
	if err != nil {
		return fmt.Errorf("encode talk: %w", err)
	}
	if err := store.kv.Put(talkkey, talkdata); err != nil {
		return fmt.Errorf("store talk: %w", err)
	}
	// Clear cache
	store.mu.Lock()
	defer store.mu.Unlock()

	// Clear hash, drop talk from cache
	store.hash = nil
	delete(store.cachemap, talk.ID)
	for i, j := 0, 0; i < len(store.cache); i++ {
		if store.cache[i].ID != talk.ID {
			store.cache[j] = store.cache[i]
			j++
		}
	}
	store.cache = store.cache[:len(store.cache)-1]
	return nil
}

func (store *Store) InsertTalk(talk *Talk) error {
	// Generate ID for talk
	id, err := store.kv.AtomicInc(store.prefix + "_count")
	if err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	talk.ID = id
	// Insert talk
	talkkey := fmt.Sprintf("%s_talks_%d", store.prefix, talk.ID)
	talkdata, err := json.Marshal(talk)
	if err != nil {
		return fmt.Errorf("encode talk: %w", err)
	}
	if err := store.kv.Put(talkkey, talkdata); err != nil {
		return fmt.Errorf("store talk: %w", err)
	}
	return nil
}

func (store *Store) Talk(id int64) (*Talk, error) {
	// List talks
	talkkeys, hash, err := store.kv.List(store.prefix + "_talks_")
	if err != nil {
		return nil, fmt.Errorf("list talks: %w", err)
	}

	// Compute hash before parsing, compare with current one
	store.mu.Lock()
	defer store.mu.Unlock()
	if bytes.Equal(hash, store.hash) {
		return store.cachemap[id], nil
	}

	// Else update cache
	if err := store.updateCache(talkkeys, hash); err != nil {
		return nil, fmt.Errorf("update cache: %w", err)
	}

	return store.cachemap[id], nil
}

// mu must be held before calling
func (store *Store) updateCache(keys []string, hash []byte) error {
	// Generate list of kept talks
	cached := make(map[string]int)
	for i := range store.cache {
		key := fmt.Sprintf("%s_talks_%d", store.prefix, store.cache[i].ID)
		cached[key] = i
	}

	// Go through each key and fetch talk
	talks := make([]*Talk, len(keys))
	talkmap := make(map[int64]*Talk)
	for i, key := range keys {
		if j, ok := cached[key]; ok {
			// Copy over from cache
			talks[i] = store.cache[j]
		} else {
			// Fetch new talk
			talkdata, err := store.kv.Fetch(key)
			if err != nil {
				return fmt.Errorf("fetch talk list: %w", err)
			}
			talks[i] = &Talk{}
			if err := json.Unmarshal(talkdata, talks[i]); err != nil {
				return fmt.Errorf("parse talk: %w", err)
			}
		}
		// TODO(lnsp): Compute talk scores and ranks
		talks[i].Rank = int64(i + 1)
		talkmap[talks[i].ID] = talks[i]
	}

	// Update cache and hash
	store.hash = hash
	store.cache = talks
	store.cachemap = talkmap
	return nil
}

func (store *Store) UpcomingTalks() ([]*Talk, error) {
	talks, err := store.Talks()
	if err != nil {
		return nil, err
	}
	// Filter out and only retain upcoming talks
	i := 0
	t := time.Now().Truncate(time.Hour * 24)
	for j := range talks {
		if talks[j].Date.Truncate(time.Hour * 24).Before(t) {
			continue
		}
		talks[i] = talks[j]
		i++
	}
	return talks[:i], nil
}

func (store *Store) Talks() ([]*Talk, error) {
	// List talks
	talkkeys, hash, err := store.kv.List(store.prefix + "_talks_")
	if err != nil {
		return nil, fmt.Errorf("list talks: %w", err)
	}

	// Compute hash before parsing, compare with current one
	store.mu.Lock()
	defer store.mu.Unlock()

	slice := make([]*Talk, len(store.cache))
	copy(slice, store.cache)

	if bytes.Equal(hash, store.hash) {
		return slice, nil
	}

	// Else update cache
	if err := store.updateCache(talkkeys, hash); err != nil {
		return nil, fmt.Errorf("update cache: %w", err)
	}

	slice = make([]*Talk, len(store.cache))
	copy(slice, store.cache)
	return slice, nil
}
