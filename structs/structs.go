package structs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lnsp/tum.events/kv"
	"github.com/microcosm-cc/bluemonday"
	"github.com/sirupsen/logrus"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"golang.org/x/sync/errgroup"
)

var TalkCategories = []string{
	"software-engineering",
	"distributed-systems",
	"programming-languages",
	"databases",
	"scientific-computing",
	"robotics",
	"artificial-intelligence",
	"automata-theory",
	"computer-networks",
	"computer-vision",
	"computer-architecture",
	"bioinformatics",
	"operating-systems",
	"data-structures",
	"computer-graphics",
	"medicine",
	"computer-security",
	"logic",
	"data-analytics",
	"machine-learning",
	"formal-methods",
	"master-thesis",
	"bachelor-thesis",
}

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

type User struct {
	ID     string   `json:"i"`
	Editor []string `json:"e"`
	Admin  bool     `json:"a"`
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
	ID         int64     `json:"i,omitempty"`
	Rank       int64     `json:"-"`
	User       string    `json:"u"`
	Title      string    `json:"t"`
	Category   string    `json:"c"`
	Date       time.Time `json:"d"`
	Link       string    `json:"l,omitempty"`
	LinkDomain string    `json:"-"`
	Body       string    `json:"b,omitempty"`
}

func (t *Talk) deriveLinkDomain() error {
	if t.Link == "" {
		return nil
	}
	u, err := url.Parse(t.Link)
	if err != nil {
		return err
	}
	t.LinkDomain = strings.TrimPrefix(u.Host, "www.")
	return nil
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
	sanitizePolicy.AllowElements("p", "pre", "code")
}

func (t *Talk) RenderAsHTML() string {
	var buf bytes.Buffer
	markdownRenderer.Convert([]byte(t.Body), &buf)
	sanitized := sanitizePolicy.SanitizeBytes(buf.Bytes())
	return string(sanitized)
}

// Storage provides capabilities to access and manage both user and individual post data.
type Storage struct {
	kv     kv.Store
	prefix string

	mu       sync.Mutex
	cache    []*Talk
	cachemap map[int64]*Talk
	hash     []byte
}

func NewStorage(backend kv.Store, prefix string) *Storage {
	return &Storage{
		prefix: prefix,
		kv:     backend,
	}
}

const maxConcurrentLogins = 3
const expirationInterval = 15 * time.Minute
const secretLength = 32

func (storage *Storage) HasTooManyLogins(user string) (bool, int, error) {
	// List all logins
	loginkeys, _, err := storage.kv.List(storage.prefix + "_login_")
	if err != nil {
		return false, -1, fmt.Errorf("fetch logins: %w", err)
	}
	// Go through each login and check
	concurrentLogins := 0
	minDelay := -1
	for _, key := range loginkeys {
		data, err := storage.kv.Fetch(key)
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
			if err := storage.kv.Delete(key); err != nil {
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

func (storage *Storage) HasActiveVerification(user string) (bool, error) {
	// List all verifications
	verifkeys, _, err := storage.kv.List(storage.prefix + "_verif_")
	if err != nil {
		return false, fmt.Errorf("fetch verifications: %w", err)
	}
	// Go through each verification and check
	for _, key := range verifkeys {
		data, err := storage.kv.Fetch(key)
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
			if err := storage.kv.Delete(key); err != nil {
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

const sessionExpiration = 24 * time.Hour * 30
const loginExpiration = 10 * time.Minute
const loginKeyLen = 32
const loginCodeLen = 6

var (
	ErrLoginInvalidKey = errors.New("invalid key")
	ErrLoginExpired    = errors.New("login expired")
	ErrInvalidInput    = errors.New("invalid input")
)

type TooManyLoginsError struct {
	Timeout int
}

func (err TooManyLoginsError) Error() string {
	return fmt.Sprintf("too many logins, try again in %d seconds", err.Timeout)
}

type WrongCodeError struct {
	Attempt     int
	MaxAttempts int
}

func (err WrongCodeError) Error() string {
	return fmt.Sprintf("wrong code, attempt %d of %d", err.Attempt, err.MaxAttempts)
}

func (storage *Storage) ConfirmLogin(key, code string) (*Session, *Login, error) {
	// Check that key is 32-byte hex string
	if keyBytes, err := hex.DecodeString(key); err != nil || len(keyBytes) != 32 {
		return nil, nil, ErrLoginInvalidKey
	}
	// Fetch login with given key
	loginKey := fmt.Sprintf("%s_login_%s", storage.prefix, key)
	data, err := storage.kv.Fetch(loginKey)
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
		if err := storage.kv.Delete(loginKey); err != nil {
			return nil, nil, fmt.Errorf("delete login: %w", err)
		}
		return nil, nil, ErrLoginExpired
	}
	data, err = json.Marshal(login)
	if err != nil {
		return nil, nil, fmt.Errorf("encode login: %w", err)
	}
	if err := storage.kv.Put(loginKey, data); err != nil {
		return nil, nil, fmt.Errorf("store login: %w", err)
	}
	// Make sure that code matches
	if login.Code != code {
		return nil, &login, WrongCodeError{Attempt: login.Attempt, MaxAttempts: LoginMaxAttempts}
	}
	// Delete login, turn into session
	if err := storage.kv.Delete(loginKey); err != nil {
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
	sessionKey := fmt.Sprintf("%s_session_%s", storage.prefix, key)
	if err := storage.kv.Put(sessionKey, data); err != nil {
		return nil, nil, fmt.Errorf("store session: %w", err)
	}
	return &session, &login, nil
}

func (storage *Storage) DeleteSession(key string) error {
	// Check if key with session exists
	if err := storage.kv.Delete(fmt.Sprintf("%s_session_%s", storage.prefix, key)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (storage *Storage) VerifySession(key string) (string, error) {
	// Fetch session
	data, err := storage.kv.Fetch(fmt.Sprintf("%s_session_%s", storage.prefix, key))
	if err != nil {
		return "", fmt.Errorf("fetch session: %w", err)
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return "", fmt.Errorf("decode session: %w", err)
	}
	// Make sure that session is active, else delete
	if !session.Active() {
		if err := storage.DeleteSession(key); err != nil {
			return "", err
		}
		return "", nil
	}
	// Return user
	return session.User, nil
}

func (storage *Storage) AttemptLogin(user string) (*Login, error) {
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
	key := fmt.Sprintf("%s_login_%s", storage.prefix, keyString)
	if err := storage.kv.Put(key, loginJSON); err != nil {
		return nil, fmt.Errorf("store login: %w", err)
	}
	return login, nil
}

func (storage *Storage) Verify(secret string) error {
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
	key := fmt.Sprintf("%s_verif_%s", storage.prefix, secret)
	verifdata, err := storage.kv.Fetch(key)
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
	if err := storage.kv.Delete(key); err != nil {
		return fmt.Errorf("delete verification: %w", err)
	}
	return storage.InsertTalk(verif.Talk)
}

func (storage *Storage) DeleteTalk(ids ...int64) error {
	for _, id := range ids {
		talkkey := fmt.Sprintf("%s_talks_%d", storage.prefix, id)
		if err := storage.kv.Delete(talkkey); err != nil {
			return fmt.Errorf("delete talk: %w", err)
		}
	}

	// Build ID set for quick lookup later on.
	idset := map[int64]struct{}{}
	for _, id := range ids {
		idset[id] = struct{}{}
	}

	// Clear cache
	storage.mu.Lock()
	defer storage.mu.Unlock()

	// Clear hash, drop talk from cache
	storage.hash = nil

	for id := range idset {
		delete(storage.cachemap, id)
	}
	i, j := 0, 0
	for ; i < len(storage.cache); i++ {
		if _, ok := idset[storage.cache[i].ID]; !ok {
			storage.cache[j] = storage.cache[i]
			j++
		}
	}
	storage.cache = storage.cache[:j]
	return nil
}

func (storage *Storage) UpdateTalk(talk *Talk) error {
	if talk.ID == 0 {
		return fmt.Errorf("talk id required")
	}
	talkkey := fmt.Sprintf("%s_talks_%d", storage.prefix, talk.ID)
	talkdata, err := json.Marshal(talk)
	if err != nil {
		return fmt.Errorf("encode talk: %w", err)
	}
	if err := storage.kv.Put(talkkey, talkdata); err != nil {
		return fmt.Errorf("store talk: %w", err)
	}
	// Clear cache
	storage.mu.Lock()
	defer storage.mu.Unlock()

	// Clear hash, drop talk from cache
	storage.hash = nil
	delete(storage.cachemap, talk.ID)
	for i, j := 0, 0; i < len(storage.cache); i++ {
		if storage.cache[i].ID != talk.ID {
			storage.cache[j] = storage.cache[i]
			j++
		}
	}
	storage.cache = storage.cache[:len(storage.cache)-1]
	return nil
}

func (storage *Storage) InsertTalk(talk *Talk) error {
	// Generate ID for talk
	id, err := storage.kv.AtomicInc(storage.prefix + "_count")
	if err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	talk.ID = id
	// Insert talk
	talkkey := fmt.Sprintf("%s_talks_%d", storage.prefix, talk.ID)
	talkdata, err := json.Marshal(talk)
	if err != nil {
		return fmt.Errorf("encode talk: %w", err)
	}
	if err := storage.kv.Put(talkkey, talkdata); err != nil {
		return fmt.Errorf("store talk: %w", err)
	}
	return nil
}

func (storage *Storage) Talk(id int64) (*Talk, error) {
	// List talks
	talkkeys, hash, err := storage.kv.List(storage.prefix + "_talks_")
	if err != nil {
		return nil, fmt.Errorf("list talks: %w", err)
	}

	// Compute hash before parsing, compare with current one
	storage.mu.Lock()
	defer storage.mu.Unlock()
	if bytes.Equal(hash, storage.hash) {
		return storage.cachemap[id], nil
	}

	// Else update cache
	logrus.WithFields(logrus.Fields{
		"got_hash":      hex.EncodeToString(hash),
		"expected_hash": hex.EncodeToString(storage.hash),
	}).Debug("Mismatching hashes, updating cache")
	if err := storage.updateCache(talkkeys, hash); err != nil {
		return nil, fmt.Errorf("update cache: %w", err)
	}

	return storage.cachemap[id], nil
}

const numUpdateCacheWorkers = 8

// mu must be held before calling
func (storage *Storage) updateCache(keys []string, hash []byte) error {
	// Start measuring update cache op
	opStart := time.Now()

	// Generate list of kept talks
	cached := make(map[string]int)
	for i := range storage.cache {
		key := fmt.Sprintf("%s_talks_%d", storage.prefix, storage.cache[i].ID)
		cached[key] = i
	}

	// Go through each key and fetch talk concurrently
	talks := make([]*Talk, len(keys))
	talkmap := make(map[int64]*Talk)
	// Start up worker pool with N goroutines
	type workQueueItem struct {
		Index int
		Key   string
	}
	group := &errgroup.Group{}
	workQueue := make(chan workQueueItem, numUpdateCacheWorkers)
	for i := 0; i < numUpdateCacheWorkers; i++ {
		group.Go(func() error {
			for wqi := range workQueue {
				talkdata, err := storage.kv.Fetch(wqi.Key)
				if err != nil {
					return fmt.Errorf("fetch talk: %w", err)
				}
				if err := json.Unmarshal(talkdata, talks[wqi.Index]); err != nil {
					return fmt.Errorf("parse talk: %w", err)
				}
				talks[wqi.Index].deriveLinkDomain()
			}
			return nil
		})
	}
	// Send out required computations
	diffcount := 0
	for i, key := range keys {
		if j, ok := cached[key]; ok {
			talks[i] = storage.cache[j]
		} else {
			talks[i] = &Talk{}
			workQueue <- workQueueItem{Index: i, Key: key}
			diffcount++
		}
	}
	close(workQueue)
	// Wait for all workers to finish
	if err := group.Wait(); err != nil {
		logrus.WithError(err).Warn("Got err while updating cache")
		return err
	}
	// TODO(lnsp): Compute talk scores, ranks
	for i := range keys {
		talks[i].Rank = int64(i + 1)
		talkmap[talks[i].ID] = talks[i]
	}
	// Update cache and hash
	storage.hash = hash
	storage.cache = talks
	storage.cachemap = talkmap

	// Report status in log
	opEnd := time.Now()
	logrus.WithFields(logrus.Fields{
		"hash":     hex.EncodeToString(hash),
		"diff":     diffcount,
		"duration": opEnd.Sub(opStart),
	}).Debug("Successfully updated cache")
	return nil
}

func (storage *Storage) UpcomingTalks() ([]*Talk, error) {
	talks, err := storage.Talks()
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

func (storage *Storage) Talks() ([]*Talk, error) {
	// List talks
	talkkeys, hash, err := storage.kv.List(storage.prefix + "_talks_")
	if err != nil {
		return nil, fmt.Errorf("list talks: %w", err)
	}

	// Compute hash before parsing, compare with current one
	storage.mu.Lock()
	defer storage.mu.Unlock()

	slice := make([]*Talk, len(storage.cache))
	copy(slice, storage.cache)

	if bytes.Equal(hash, storage.hash) {
		return slice, nil
	}

	// Else update cache
	if err := storage.updateCache(talkkeys, hash); err != nil {
		return nil, fmt.Errorf("update cache: %w", err)
	}

	slice = make([]*Talk, len(storage.cache))
	copy(slice, storage.cache)
	return slice, nil
}

func (storage *Storage) User(id string) (*User, error) {
	userdata, err := storage.kv.Fetch(storage.prefix + "_users_" + id)
	if err != nil {
		return nil, err
	}
	var user User
	if err := json.Unmarshal(userdata, &user); err != nil {
		return nil, err
	}
	return &user, nil
}
