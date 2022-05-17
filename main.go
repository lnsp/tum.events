package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/mailgun/mailgun-go/v4"
	"github.com/sirupsen/logrus"

	_ "time/tzdata"
)

//go:embed favicon.png
var favicon []byte

//go:embed tailwind.min.css
var tailwindStyles []byte

//go:embed template/*
var webTemplates embed.FS

//go:embed email/*
var emailTemplates embed.FS

var talkCategories = []string{
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
}

func main() {
	mail := NewMailProvider(&MailConfig{
		Sender:       os.Getenv("MAIL_SENDER"),
		SenderDomain: os.Getenv("MAIL_DOMAIN"),
		APIKey:       os.Getenv("MAIL_APIKEY"),
		UserDomain:   os.Getenv("MAIL_USERDOMAIN"),
	}, emailTemplates)
	store := NewTalkStore(&KVCreds{
		Token:   os.Getenv("VALAR_TOKEN"),
		Project: os.Getenv("VALAR_PROJECT"),
	}, os.Getenv("VALAR_PREFIX"))
	publicURL, err := url.Parse(os.Getenv("ROUTER_PUBLICURL"))
	if err != nil {
		logrus.WithError(err).Fatal("public url is invalid")
	}
	router := NewRouter(publicURL, store, mail)
	router.setup()
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		Handler:      router,
	}
	if err := server.ListenAndServe(); err != nil {
		logrus.WithError(err).Fatal("listen and serve")
	}
}

var templateFuncs = template.FuncMap{
	"humandate": func(t time.Time) string {
		return t.Format("02.01.2006 15:04")
	},
}

type Router struct {
	publicURL *url.URL
	mux       *mux.Router
	store     *TalkStore
	mail      *MailProvider

	templates map[string]*template.Template
}

func (router *Router) setup() {
	// setup routes
	router.mux.Handle("/", router.top()).Methods("GET")
	router.mux.Handle("/top", router.top()).Methods("GET")
	router.mux.Handle("/nextup", router.nextup()).Methods("GET")
	router.mux.Handle("/categories", router.categories()).Methods("GET")
	router.mux.Handle("/categories/{category}", router.category()).Methods("GET")
	router.mux.Handle("/talk/{id}", router.talk()).Methods("GET")
	router.mux.Handle("/submit", router.submit()).Methods("GET")
	router.mux.Handle("/submit", router.accept()).Methods("POST")
	router.mux.Handle("/verify/{secret}", router.confirm()).Methods("GET")
	router.mux.Handle("/verify/{secret}", router.verify()).Methods("POST")
	router.mux.Handle("/styles.css", router.styles()).Methods("GET")
	router.mux.Handle("/favicon.png", router.favicon()).Methods("GET")
	router.mux.Handle("/legal", router.legal()).Methods("GET")
	// parse templates
	router.templates = make(map[string]*template.Template)
	for _, t := range []string{"template/categories.html", "template/submit.html", "template/top.html", "template/confirm.html", "template/legal.html", "template/talk.html"} {
		router.templates[path.Base(t)] = template.Must(template.New("base.html").Funcs(templateFuncs).ParseFS(webTemplates, "template/base.html", t))
	}
}

func (router *Router) submit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		context := struct{ Categories []string }{talkCategories}
		if err := router.templates["submit.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
		}
	})
}

var userRegex = regexp.MustCompile(`^[a-z]{2}[0-9]{2}[a-z]{3}$`)
var titleRegex = regexp.MustCompile(`^[\d\s\w?!:]{10,128}$`)
var linkSchemeRegex = regexp.MustCompile(`^http(s)?$`)

const bodyCharLimit = 10000

const localTimeFormat = "2006-01-02T15:04"

func (router *Router) confirm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := router.templates["confirm.html"].Execute(w, &struct{ Talk bool }{true}); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) verify() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := mux.Vars(r)["secret"]
		if err := router.store.Verify(secret); err != nil {
			http.Error(w, "could not verify talk", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (router *Router) styles() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(tailwindStyles)
	})
}

func (router *Router) favicon() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(favicon)
	})
}

func (router *Router) legal() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := router.templates["legal.html"].Execute(w, nil); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) talk() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
		if err != nil {
			http.Error(w, "invalid talk id", http.StatusBadRequest)
			return
		}
		talk, err := router.store.Talk(id)
		if err != nil {
			http.Error(w, "could not fetch talk", http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to fetch talk")
			return
		} else if talk == nil {
			http.Error(w, "talk not found", http.StatusNotFound)
			return
		}
		ctx := struct {
			Talk *Talk
		}{
			talk,
		}
		if err := router.templates["talk.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
			return
		}
	})
}

func (router *Router) accept() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}
		// Verify items one by one
		user := r.Form.Get("uid")
		if !userRegex.MatchString(user) {
			http.Error(w, "user not valid", http.StatusBadRequest)
			return
		}
		// Title must at max contain 128 characters, and at least 10 non-whitespace ones
		title := r.Form.Get("title")
		if len(strings.TrimSpace(title)) < 10 || !titleRegex.MatchString(title) {
			http.Error(w, "title not valid", http.StatusBadRequest)
			return
		}
		body := r.Form.Get("body")
		// Make sure that we don't go over the character limit
		if len(body) > bodyCharLimit {
			http.Error(w, "body has more than 10000 characters", http.StatusBadRequest)
			return
		}
		// Verify that either link is valid URL and has http scheme
		link := r.Form.Get("url")
		parsedLink, err := url.Parse(link)
		if link != "" && err != nil {
			http.Error(w, "link not valid", http.StatusBadRequest)
			return
		} else if link != "" && !linkSchemeRegex.MatchString(parsedLink.Scheme) {
			http.Error(w, "link must be http or https", http.StatusBadRequest)
			return
		}
		// Verify that category is in categories list
		category := r.Form.Get("category")
		categoryExists := false
		for i := range talkCategories {
			if talkCategories[i] == category {
				categoryExists = true
				break
			}
		}
		if !categoryExists {
			http.Error(w, "category does not exist", http.StatusBadRequest)
			return
		}
		// Verify that date is in the future
		location, _ := time.LoadLocation("Europe/Berlin")
		date, err := time.ParseInLocation(localTimeFormat, r.Form.Get("date"), location)
		if err != nil {
			http.Error(w, "could not parse datetime", http.StatusBadRequest)
			return
		}
		if time.Since(date) >= 0 {
			http.Error(w, "date has to be in the future", http.StatusBadRequest)
			return
		}
		// Check if there are any open verifications for this user
		if ok, err := router.store.HasActiveVerification(user); err != nil {
			http.Error(w, "failed to check verifications", http.StatusInternalServerError)
			return
		} else if ok {
			http.Error(w, "user has active verifications", http.StatusForbidden)
			return
		}
		// Generate talk object and add to talk store
		talk := &Talk{
			User:     user,
			Title:    title,
			Category: category,
			Date:     date,
			Link:     link,
			Body:     body,
		}
		secret, err := router.store.Add(talk)
		if err != nil {
			http.Error(w, "could not create verification", http.StatusInternalServerError)
			return
		}
		// Render verification link
		verificationLink := &url.URL{
			Scheme: router.publicURL.Scheme,
			Host:   router.publicURL.Host,
			Path:   "/verify/" + secret,
		}
		// Send out verification link via email
		if err := router.mail.SendVerification(user, verificationLink.String(), talk); err != nil {
			logrus.WithError(err).Error("Failed to send email")
			http.Error(w, "sending verification failed", http.StatusInternalServerError)
			return
		}
		// Render confirm template
		if err := router.templates["confirm.html"].Execute(w, &struct{ Talk bool }{}); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
			return
		}
	})
}

func (router *Router) top() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		talks, err := router.store.UpcomingTalks()
		if err != nil {
			http.Error(w, "could not retrieve talks", http.StatusInternalServerError)
			return
		}
		sort.Slice(talks, func(i, j int) bool { return talks[i].Rank < talks[j].Rank })

		context := struct {
			Talks []*Talk
		}{
			talks,
		}
		if err := router.templates["top.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) nextup() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get talks sorted by date
		talks, err := router.store.UpcomingTalks()
		if err != nil {
			http.Error(w, "could not retrieve talks", http.StatusInternalServerError)
			return
		}
		sort.Slice(talks, func(i, j int) bool { return talks[i].Date.Before(talks[j].Date) })

		// Put into top context
		context := struct {
			Talks []*Talk
		}{
			talks,
		}
		if err := router.templates["top.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) categories() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Put into top context
		context := struct {
			Category   bool
			Categories []string
		}{
			false,
			talkCategories,
		}
		if err := router.templates["categories.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) category() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get category
		category := mux.Vars(r)["category"]
		// Check that category is in 'valid' categories
		found := false
		for _, c := range talkCategories {
			if c == category {
				found = true
			}
		}
		if !found {
			http.Error(w, "category not found", http.StatusNotFound)
			return
		}
		// Put into top context
		talks, err := router.store.UpcomingTalks()
		if err != nil {
			http.Error(w, "could not retrieve talks", http.StatusInternalServerError)
			return
		}
		// Filter talks by category
		j := 0
		for i := range talks {
			if talks[i].Category == category {
				talks[j] = talks[i]
				j++
			}
		}
		talks = talks[:j]
		// Sort by date
		sort.Slice(talks, func(i, j int) bool { return talks[i].Date.Before(talks[j].Date) })

		context := struct {
			Category string
			Talks    []*Talk
		}{
			Category: category,
			Talks:    talks,
		}
		if err := router.templates["categories.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func NewRouter(publicURL *url.URL, store *TalkStore, mail *MailProvider) *Router {
	return &Router{
		mux:       mux.NewRouter(),
		publicURL: publicURL,
		store:     store,
		mail:      mail,
	}
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := time.Now()
	router.mux.ServeHTTP(w, r)
	d := time.Since(s)

	logrus.WithFields(logrus.Fields{
		"duration": d,
		"path":     r.URL.Path,
		"method":   r.Method,
	}).Info("Served request")
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

type KVCreds struct {
	Token   string
	Project string
}

type MailConfig struct {
	Sender       string
	SenderDomain string
	APIKey       string
	UserDomain   string
}

type MailProvider struct {
	mg         mailgun.Mailgun
	sender     string
	template   *template.Template
	userdomain string
}

func NewMailProvider(cfg *MailConfig, templates fs.FS) *MailProvider {
	mg := mailgun.NewMailgun(cfg.SenderDomain, cfg.APIKey)
	mg.SetAPIBase(mailgun.APIBaseEU)

	return &MailProvider{
		mg:         mg,
		sender:     cfg.Sender,
		template:   template.Must(template.New("verify.html").Funcs(templateFuncs).ParseFS(templates, "email/*.html")),
		userdomain: cfg.UserDomain,
	}
}

func (mp *MailProvider) SendVerification(user, link string, talk *Talk) error {
	emailData := struct {
		Talk       *Talk
		Stylesheet template.CSS
		Link       string
	}{
		Talk:       talk,
		Stylesheet: template.CSS(string(tailwindStyles)),
		Link:       link,
	}
	var buf bytes.Buffer
	if err := mp.template.Execute(&buf, &emailData); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	message := mp.mg.NewMessage(mp.sender, "Please verify your talk - IN.TUM Talks", "", user+"@"+mp.userdomain)
	message.SetHtml(buf.String())
	if _, _, err := mp.mg.Send(ctx, message); err != nil {
		return fmt.Errorf("send mail: %w", err)
	}
	return nil
}

type TalkStore struct {
	kv     *KVStore
	prefix string

	mu       sync.Mutex
	cache    []*Talk
	cachemap map[int64]*Talk
	hash     []byte
}

func NewTalkStore(creds *KVCreds, prefix string) *TalkStore {
	return &TalkStore{
		prefix: prefix,
		kv: &KVStore{
			KVCreds: creds,
		},
	}
}

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

const expirationInterval = 15 * time.Minute
const secretLength = 32

func (store *TalkStore) HasActiveVerification(user string) (bool, error) {
	// List all verifications
	verifkeys, _, err := store.kv.list(store.prefix + "_verif_")
	if err != nil {
		return false, fmt.Errorf("fetch verifications: %w", err)
	}
	// Go through each verification and check
	for _, key := range verifkeys {
		data, err := store.kv.fetch(key)
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
			if err := store.kv.delete(key); err != nil {
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

func (store *TalkStore) Add(talk *Talk) (string, error) {
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
	if err := store.kv.put(key, data); err != nil {
		return "", fmt.Errorf("store verification: %w", err)
	}
	return secret, nil
}

func (store *TalkStore) Verify(secret string) error {
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
	verifdata, err := store.kv.fetch(key)
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
	if err := store.kv.delete(key); err != nil {
		return fmt.Errorf("delete verification: %w", err)
	}
	// Generate ID for talk
	id, err := store.kv.atomicinc(store.prefix + "_count")
	if err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	talk := verif.Talk
	talk.ID = id
	// Insert talk
	talkkey := fmt.Sprintf("%s_talks_%d", store.prefix, talk.ID)
	talkdata, err := json.Marshal(talk)
	if err != nil {
		return fmt.Errorf("encode talk: %w", err)
	}
	if err := store.kv.put(talkkey, talkdata); err != nil {
		return fmt.Errorf("store talk: %w", err)
	}
	return nil
}

func (store *TalkStore) Talk(id int64) (*Talk, error) {
	// List talks
	talkkeys, hash, err := store.kv.list(store.prefix + "_talks_")
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
func (store *TalkStore) updateCache(keys []string, hash []byte) error {
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
			continue
		} else {
			// Fetch new talk
			talkdata, err := store.kv.fetch(key)
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

func (store *TalkStore) UpcomingTalks() ([]*Talk, error) {
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

func (store *TalkStore) Talks() ([]*Talk, error) {
	// List talks
	talkkeys, hash, err := store.kv.list(store.prefix + "_talks_")
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
