package main

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/lnsp/tumtalks/kv"
	"github.com/lnsp/tumtalks/mail"
	"github.com/lnsp/tumtalks/structs"
	"github.com/sirupsen/logrus"

	_ "time/tzdata"
)

//go:embed favicon.png
var favicon []byte

//go:embed templates/*.html
var webTemplates embed.FS

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
	"formal-methods",
}

const authCookieKey = "auth"

func main() {
	mail := mail.NewProvider(&mail.Config{
		Sender:       os.Getenv("MAIL_SENDER"),
		SenderDomain: os.Getenv("MAIL_DOMAIN"),
		APIKey:       os.Getenv("MAIL_APIKEY"),
		UserDomain:   os.Getenv("MAIL_USERDOMAIN"),
	})
	store := structs.NewStore(&kv.Credentials{
		Token:   os.Getenv("VALAR_TOKEN"),
		Project: os.Getenv("VALAR_PROJECT"),
	}, os.Getenv("VALAR_PREFIX"))
	publicURL, err := url.Parse(os.Getenv("ROUTER_PUBLICURL"))
	if err != nil {
		logrus.WithError(err).Fatal("public url is invalid")
	}
	httpsOnly := os.Getenv("ROUTER_HTTPSONLY") != ""
	router := NewRouter(publicURL, store, mail, httpsOnly)
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
	"inc": func(i int) int {
		return i + 1
	},
}

//go:embed templates/tailwind.min.css
var tailwindStyles []byte

type Router struct {
	publicURL *url.URL
	mux       *mux.Router
	store     *structs.Store
	mail      *mail.Provider
	httpsOnly bool

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
	router.mux.Handle("/submit", router.submitForm()).Methods("POST")
	router.mux.Handle("/verify/{secret}", router.confirm()).Methods("GET")
	router.mux.Handle("/verify/{secret}", router.verify()).Methods("POST")
	router.mux.Handle("/styles.css", router.styles()).Methods("GET")
	router.mux.Handle("/favicon.png", router.favicon()).Methods("GET")
	router.mux.Handle("/legal", router.legal()).Methods("GET")
	router.mux.Handle("/login", router.loginWithCode()).Methods("POST").Queries("method", "code")
	router.mux.Handle("/login", router.login()).Methods("GET")
	router.mux.Handle("/login", router.loginForm()).Methods("POST")
	router.mux.Handle("/logout", router.logout()).Methods("POST")
	// parse templates
	router.templates = make(map[string]*template.Template)
	for _, t := range []string{"templates/categories.html", "templates/submit.html", "templates/top.html", "templates/confirm.html", "templates/legal.html", "templates/talk.html", "templates/login.html", "templates/login-code.html"} {
		router.templates[path.Base(t)] = template.Must(template.New("base.html").Funcs(templateFuncs).ParseFS(webTemplates, "templates/base.html", t))
	}
}

func (router *Router) submit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		context := struct {
			*authCtx
			Categories []string
		}{router.authCtxFromRequest(w, r), talkCategories}
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
		if err := router.templates["confirm.html"].Execute(w, &struct {
			*authCtx
			Talk bool
		}{router.authCtxFromRequest(w, r), true}); err != nil {
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
		if err := router.templates["legal.html"].Execute(w, router.authCtxFromRequest(w, r)); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := router.authCtxFromRequest(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		ctx := struct {
			*authCtx
			Error string
		}{
			authCtx: ac,
		}
		// Else show login form
		if err := router.templates["login.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func (router *Router) loginForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := router.authCtxFromRequest(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		showError := func(errorMsg string) {
			ctx := struct {
				*authCtx
				Error string
			}{
				authCtx: ac,
				Error:   errorMsg,
			}
			// Else show login form
			if err := router.templates["login.html"].Execute(w, &ctx); err != nil {
				logrus.WithError(err).Error("Failed to execute template")
				http.Error(w, "rendering failed", http.StatusInternalServerError)
			}
		}
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}
		// Else validate input
		user := r.Form.Get("uid")
		if !userRegex.MatchString(user) {
			showError("The username is not valid.")
			return
		}

		// Check that there is no active login attempt
		active, timeout, err := router.store.HasTooManyLogins(user)
		if err != nil {
			http.Error(w, "could not check logins", http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to check logins")
			return
		}
		if active {
			errorMsg := fmt.Sprintf("Too many concurrent login attempts. Please wait %d seconds before trying again.", timeout)
			showError(errorMsg)
			return
		}

		// Create login attempt
		login, err := router.store.AttemptLogin(user)
		if err != nil {
			http.Error(w, "could not create login", http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to create login")
			return
		}

		// Send out email
		if err := router.mail.SendLogin(login.User, login.Code); err != nil {
			http.Error(w, "could not send login code", http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to send login code")
			return
		}

		// Render confirm site
		ctx := struct {
			*authCtx
			Key   string
			Error string
		}{
			authCtx: ac,
			Key:     login.Key,
		}
		if err := router.templates["login-code.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
			return
		}
	})
}

var loginKeyRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var loginCodeRegex = regexp.MustCompile(`^[0-9]{6}$`)

const sessionCookieExpiration = time.Hour * 24 * 30

func (router *Router) loginWithCode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := router.authCtxFromRequest(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		// Get login key and code
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}
		// Verify key and code
		key := r.Form.Get("key")
		showError := func(errorMsg string) {
			// Show form again
			ctx := struct {
				*authCtx
				Key   string
				Error string
			}{
				authCtx: ac,
				Key:     key,
				Error:   errorMsg,
			}
			if err := router.templates["login-code.html"].Execute(w, &ctx); err != nil {
				logrus.WithError(err).Error("Failed to execute template")
				http.Error(w, "rendering failed", http.StatusInternalServerError)
			}
		}
		if !loginKeyRegex.MatchString(key) {
			showError("Your login key is invalid. Please try again.")
			return
		}
		code := r.Form.Get("code")
		if !loginCodeRegex.MatchString(code) {
			showError("Your code is in the wrong format. Please try again.")
			return
		}
		// Retrieve login attempt with key
		session, login, err := router.store.ConfirmLogin(key, code)
		if err == structs.ErrLoginExpired {
			// Redirect to login form
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		} else if err == structs.ErrLoginWrongCode {
			errorMsg := fmt.Sprintf("The code you entered is wrong (attempt %d of %d).", login.Attempt, structs.LoginMaxAttempts)
			showError(errorMsg)
			return
		} else if err != nil {
			http.Error(w, "could not confirm login", http.StatusInternalServerError)
			logrus.WithError(err).Warn("failed to confirm login")
			return
		}
		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session",
			Value:   session.Key,
			Expires: session.Expiration,
		})
		// Redirect to home site
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (router *Router) logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is valid, else redirect to homepage
		ac := router.authCtxFromRequest(w, r)
		if !ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		// Drop cookie in user session
		dropSessionCookie(w)
		// Delete session from store
		if err := router.store.DeleteSession(ac.SessionKey); err != nil {
			http.Error(w, "could not drop session", http.StatusInternalServerError)
			return
		}
		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

const sessionCookie = "session"

type authCtx struct {
	Login      string
	SessionKey string
}

func (a *authCtx) Authenticated() bool {
	return a.Login != ""
}

func dropSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		MaxAge: -1,
	})
}

func (router *Router) authCtxFromRequest(w http.ResponseWriter, r *http.Request) *authCtx {
	// Get request session cookie
	cookie, err := r.Cookie(sessionCookie)
	if err == http.ErrNoCookie {
		return &authCtx{}
	}
	// Get session key from cookie
	key := cookie.Value
	// Make sure that key is valid session key
	if !loginKeyRegex.MatchString(key) {
		dropSessionCookie(w)
		return &authCtx{}
	}
	user, err := router.store.VerifySession(key)
	if err != nil {
		// Delete session cookie
		dropSessionCookie(w)
		return &authCtx{}
	}
	return &authCtx{
		Login:      user,
		SessionKey: key,
	}
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
		type ctxTalk struct {
			ID       int64
			Title    string
			Date     time.Time
			Category string
			Body     template.HTML
			Link     string
		}
		ctx := struct {
			*authCtx
			Talk ctxTalk
		}{
			router.authCtxFromRequest(w, r),
			ctxTalk{
				ID:       talk.ID,
				Title:    talk.Title,
				Date:     talk.Date,
				Category: talk.Category,
				Link:     talk.Link,
				Body:     template.HTML(talk.RenderAsHTML()),
			},
		}
		if err := router.templates["talk.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
			return
		}
	})
}

func (router *Router) submitForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := router.authCtxFromRequest(w, r)
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}
		// Verify items one by one
		user := ac.Login
		if !ac.Authenticated() {
			user := r.Form.Get("uid")
			if !userRegex.MatchString(user) {
				http.Error(w, "user not valid", http.StatusBadRequest)
				return
			}
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
		// If user is authenticated, directly insert talk and redirect
		talk := &structs.Talk{
			User:     user,
			Title:    title,
			Category: category,
			Date:     date,
			Link:     link,
			Body:     body,
		}
		if ac.Authenticated() {
			if err := router.store.InsertTalk(talk); err != nil {
				logrus.WithError(err).Error("Failed to insert talk")
				http.Error(w, "inserting talk failed", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
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
		if err := router.templates["confirm.html"].Execute(w, &struct {
			*authCtx
			Talk bool
		}{ac, false}); err != nil {
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
			*authCtx
			Talks []*structs.Talk
		}{
			router.authCtxFromRequest(w, r),
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
			*authCtx
			Talks []*structs.Talk
		}{
			router.authCtxFromRequest(w, r),
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
			*authCtx
			Category   bool
			Categories []string
		}{
			router.authCtxFromRequest(w, r),
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
			*authCtx
			Category string
			Talks    []*structs.Talk
		}{
			authCtx:  router.authCtxFromRequest(w, r),
			Category: category,
			Talks:    talks,
		}
		if err := router.templates["categories.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
	})
}

func NewRouter(publicURL *url.URL, store *structs.Store, mail *mail.Provider, httpsOnly bool) *Router {
	return &Router{
		mux:       mux.NewRouter(),
		publicURL: publicURL,
		store:     store,
		mail:      mail,
		httpsOnly: httpsOnly,
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
