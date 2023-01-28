package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gorilla/mux"
	"github.com/lnsp/tumtalks/auth"
	"github.com/lnsp/tumtalks/kv"
	"github.com/lnsp/tumtalks/mail"
	"github.com/lnsp/tumtalks/structs"
	"github.com/sirupsen/logrus"

	_ "time/tzdata"

	ics "github.com/arran4/golang-ical"
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
	"master-thesis",
	"bachelor-thesis",
}

//go:generate sh -c "/bin/echo -n $VALAR_BUILD | head -c 8 > version.txt"
//go:embed version.txt
var buildID string

const authCookieKey = "auth"

func main() {
	// Setup nice logging
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&logrus.TextFormatter{CallerPrettyfier: func(f *runtime.Frame) (string, string) {
		return "", fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
	}})
	debugMode := os.Getenv("DEBUG") != ""

	mailProvider := mail.Provider(&mail.DebugProvider{})
	if !debugMode {
		mailProvider = mail.NewMailgunProvider(&mail.MailgunConfig{
			Sender:       os.Getenv("MAIL_SENDER"),
			SenderDomain: os.Getenv("MAIL_DOMAIN"),
			APIKey:       os.Getenv("MAIL_APIKEY"),
			UserDomain:   os.Getenv("MAIL_USERDOMAIN"),
		})
	}

	store := structs.NewStore(&kv.Credentials{
		Token:   os.Getenv("VALAR_TOKEN"),
		Project: os.Getenv("VALAR_PROJECT"),
	}, os.Getenv("VALAR_PREFIX"))

	authProvider := auth.Provider(&auth.DebugProvider{})
	if !debugMode {
		authProvider = &auth.VerifiedProvider{
			Mail:  mailProvider,
			Store: store,
		}
	}

	publicURL, err := url.Parse(os.Getenv("ROUTER_PUBLICURL"))
	if err != nil {
		logrus.WithError(err).Fatal("public url is invalid")
	}
	httpsOnly := os.Getenv("ROUTER_HTTPSONLY") != ""
	publicDomainOnly := os.Getenv("ROUTER_DOMAINONLY") != ""
	router := NewRouter(publicURL, store, authProvider, httpsOnly, publicDomainOnly)
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
	"formdate": func(t time.Time) string {
		location, _ := time.LoadLocation("Europe/Berlin")
		return t.In(location).Format(localTimeFormat)
	},
	"inc": func(i int) int {
		return i + 1
	},
}

//go:embed templates/tailwind.min.css
var tailwindStyles []byte

type Router struct {
	publicURL        *url.URL
	mux              *mux.Router
	store            *structs.Store
	httpsOnly        bool
	publicDomainOnly bool
	auth             auth.Provider

	templates map[string]*template.Template
}

func (router *Router) setup() {
	// setup routes
	router.mux.Handle("/", router.top()).Methods("GET")
	router.mux.Handle("/top", router.top()).Methods("GET")
	router.mux.Handle("/nextup", router.nextup()).Methods("GET")
	router.mux.Handle("/categories", router.categories()).Methods("GET")
	router.mux.Handle("/categories/{category}", router.category()).Methods("GET")
	router.mux.Handle("/talk", router.downloadTalk()).Methods("GET").Queries("id", "{id:[0-9]+}", "format", "ics")
	router.mux.Handle("/talk", router.talk()).Methods("GET").Queries("id", "{id:[0-9]+}")
	router.mux.Handle("/edit", router.edit()).Methods("GET").Queries("id", "{id:[0-9]+}")
	router.mux.Handle("/edit", router.editForm()).Methods("POST").Queries("id", "{id:[0-9]+}")
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

	// setup api routes
	apiRouter := router.mux.PathPrefix("/api").Subrouter()
	apiRouter.Handle("/talks", router.apiTalks()).Methods("GET")

	// parse templates
	router.templates = make(map[string]*template.Template)
	for _, t := range []string{"templates/categories.html", "templates/submit.html", "templates/top.html", "templates/confirm.html", "templates/legal.html", "templates/talk.html", "templates/login.html", "templates/login-code.html", "templates/edit.html"} {
		router.templates[path.Base(t)] = template.Must(template.New("base.html").Funcs(templateFuncs).ParseFS(webTemplates, "templates/base.html", t))
	}
}

func (router *Router) submit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := router.baseCtx(w, r)
		if !ac.Authenticated() {
			// Redirect to login form
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		context := struct {
			baseCtx
			Categories []string
		}{ac, talkCategories}

		if err := router.templates["submit.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
		}
	})
}

var titleRegex = regexp.MustCompile(`^[\d\s\w?!:,\-()]{10,128}$`)

func validateTitle(proposed string) bool {
	if !titleRegex.MatchString(proposed) {
		return false
	}
	// A title should consist at least 50% of letters
	count := 0
	for _, r := range proposed {
		if unicode.IsLetter(r) {
			count++
		}
	}
	return count > len(proposed)/2
}

var linkSchemeRegex = regexp.MustCompile(`^http(s)?$`)

const bodyCharLimit = 10000
const genericErrorMessage = "Something has gone awry. Please try again."
const localTimeFormat = "2006-01-02T15:04"

func (router *Router) confirm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := router.baseCtx(w, r)
		if err := router.templates["confirm.html"].Execute(w, &struct {
			baseCtx
			Talk bool
		}{ac, true}); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
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
		if err := router.templates["legal.html"].Execute(w, router.baseCtx(w, r)); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (router *Router) login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := router.baseCtx(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		ctx := struct {
			baseCtx
			Error string
		}{
			baseCtx: ac,
		}
		// Else show login form
		if err := router.templates["login.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (router *Router) edit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idstr := mux.Vars(r)["id"]
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			http.Error(w, "bad id format", http.StatusBadRequest)
			return
		}
		ac := router.baseCtx(w, r)
		if !ac.Authenticated() {
			http.Redirect(w, r, "/talk?id="+idstr, http.StatusSeeOther)
			return
		}
		// Get post with given ID
		talk, err := router.store.Talk(id)
		if talk == nil || err != nil {
			http.Error(w, "could not find talk", http.StatusNotFound)
			return
		}
		if talk.User != ac.Login {
			http.Error(w, "not the author of the talk", http.StatusForbidden)
			return
		}
		// Context should already
		ctx := struct {
			baseCtx
			Talk       *structs.Talk
			Categories []string
		}{
			baseCtx:    ac,
			Talk:       talk,
			Categories: talkCategories,
		}
		if err := router.templates["edit.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (router *Router) editForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idstr := mux.Vars(r)["id"]
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			http.Error(w, "bad id format", http.StatusBadRequest)
			return
		}
		ac := router.baseCtx(w, r)
		if !ac.Authenticated() {
			http.Redirect(w, r, "/talk?id="+idstr, http.StatusSeeOther)
			return
		}
		// Get post with given ID
		talk, err := router.store.Talk(id)
		if talk == nil || err != nil {
			http.Error(w, "could not find talk", http.StatusNotFound)
			return
		}
		if talk.User != ac.Login {
			http.Error(w, "not the author of the talk", http.StatusForbidden)
			return
		}
		// Set up basic error helper
		showError := func(errorMsg string, status int) {
			// Else show login form
			w.WriteHeader(status)
			ctx := struct {
				baseCtx
				Talk       *structs.Talk
				Categories []string
			}{
				baseCtx:    ac,
				Talk:       talk,
				Categories: talkCategories,
			}
			ctx.Error = errorMsg
			if err := router.templates["edit.html"].Execute(w, &ctx); err != nil {
				logrus.WithError(err).Error("Failed to execute template")
				return
			}
		}
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form data", http.StatusBadRequest)
			return
		}
		// If we want to delete the post, thats easy!
		if delete := r.Form.Get("delete"); delete != "" {
			if err := router.store.DeleteTalk(id); err != nil {
				http.Error(w, "could not delete talk", http.StatusInternalServerError)
				logrus.WithError(err).Error("Failed to delete talk")
				return
			}
			return
		}
		// Title must at max contain 128 characters, and at least 10 non-whitespace ones
		title := strings.TrimSpace(r.Form.Get("title"))
		if !validateTitle(title) {
			showError("Your title is invalid. It should match "+titleRegex.String()+`.`, http.StatusBadRequest)
			return
		}
		talk.Title = title

		// Make sure that we don't go over the character limit
		body := r.Form.Get("body")
		if len(body) > bodyCharLimit {
			showError("Your details body is too long. It should be no longer than 10000 characters.", http.StatusBadRequest)
			return
		}
		talk.Body = body

		// Verify that either link is valid URL and has http scheme
		link := r.Form.Get("url")
		parsedLink, err := url.Parse(link)
		if link != "" && err != nil {
			showError("Your link does not seem to be a valid URL.", http.StatusBadRequest)
			return
		} else if link != "" && !linkSchemeRegex.MatchString(parsedLink.Scheme) {
			showError("The talk links schema must be http:// or https://.", http.StatusBadRequest)
			return
		}
		talk.Link = link

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
			showError("The selected category does not exist.", http.StatusBadRequest)
			return
		}
		talk.Category = category

		// Verify that date is in the future
		location, _ := time.LoadLocation("Europe/Berlin")
		date, err := time.ParseInLocation(localTimeFormat, r.Form.Get("date"), location)
		if err != nil {
			showError("The selected date is in a non-parseable format.", http.StatusBadRequest)
			return
		}
		if time.Since(date) >= 0 {
			showError("The selected date has to be in the future.", http.StatusBadRequest)
			return
		}
		talk.Date = date
		// Update talk data
		if err := router.store.UpdateTalk(talk); err != nil {
			showError(genericErrorMessage, http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to update talk")
			return
		}
		// Redirect to talk page
		http.Redirect(w, r, "/talk?id="+idstr, http.StatusSeeOther)
	})
}

func (router *Router) loginForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := router.baseCtx(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		showError := func(errorMsg string, status int) {
			ac.Error = errorMsg
			// Else show login form
			w.WriteHeader(status)
			if err := router.templates["login.html"].Execute(w, &ac); err != nil {
				logrus.WithError(err).Error("Failed to execute template")
				return
			}
		}
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}
		// Else validate input
		user := r.Form.Get("uid")
		login, err := router.auth.Login(user)
		if errors.Is(err, structs.ErrInvalidInput) {
			showError("Please check your username.", http.StatusBadRequest)
			return
		} else if loginErr := (structs.TooManyLoginsError{}); errors.As(err, &loginErr) {
			showError(fmt.Sprintf("Too many login attempts. Please try again in %d seconds.", loginErr.Timeout), http.StatusTooManyRequests)
			return
		} else if err != nil {
			showError(genericErrorMessage, http.StatusInternalServerError)
			return
		}
		// Render confirm site
		ctx := struct {
			baseCtx
			Key string
		}{
			baseCtx: ac,
			Key:     login.Key,
		}
		if err := router.templates["login-code.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
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
		ac := router.baseCtx(w, r)
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
				baseCtx
				Key string
			}{
				baseCtx: ac,
				Key:     key,
			}
			ctx.Error = errorMsg
			if err := router.templates["login-code.html"].Execute(w, &ctx); err != nil {
				logrus.WithError(err).Error("Failed to execute template")
				return
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
		session, err := router.auth.LoginWithCode(key, code)
		if errors.Is(err, structs.ErrLoginInvalidKey) {
			// Redirect to login form
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		} else if wrongCodeErr := (structs.WrongCodeError{}); errors.As(err, &wrongCodeErr) {
			errorMsg := fmt.Sprintf("The code you entered is wrong (attempt %d of %d).", wrongCodeErr.Attempt, wrongCodeErr.MaxAttempts)
			showError(errorMsg)
			return
		} else if err != nil {
			logrus.WithError(err).Warn("Failed to confirm login")
			showError(genericErrorMessage)
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
		ac := router.baseCtx(w, r)
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

type baseCtx struct {
	Build      string
	Error      string
	Login      string
	SessionKey string
}

func (a *baseCtx) Authenticated() bool {
	return a.Login != ""
}

func dropSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		MaxAge: -1,
	})
}

func (router *Router) baseCtx(w http.ResponseWriter, r *http.Request) baseCtx {
	ctx := baseCtx{Build: buildID}
	// Get request session cookie
	cookie, err := r.Cookie(sessionCookie)
	if err == http.ErrNoCookie {
		return ctx
	}
	// Get session key from cookie
	key := cookie.Value
	// Make sure that key is valid session key
	if !loginKeyRegex.MatchString(key) {
		dropSessionCookie(w)
		return ctx
	}
	user, err := router.store.VerifySession(key)
	if err != nil {
		// Delete session cookie
		dropSessionCookie(w)
		return ctx
	}
	ctx.Login = user
	ctx.SessionKey = key
	return ctx
}

func (router *Router) downloadTalk() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
		if err != nil {
			http.Error(w, "invalid talk id", http.StatusBadRequest)
			return
		}
		talk, err := router.store.Talk(id)
		if talk == nil || err != nil {
			http.Error(w, "could not fetch talk", http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to fetch talk")
			return
		} else if talk == nil {
			http.Error(w, "talk not found", http.StatusNotFound)
			return
		}
		// Encode talk as ICS
		cal := ics.NewCalendar()
		cal.SetMethod(ics.MethodRequest)
		event := cal.AddEvent(fmt.Sprintf("%d@tum.events", id))
		event.SetCreatedTime(time.Now())
		event.SetStartAt(talk.Date)
		event.SetEndAt(talk.Date.Add(time.Hour))
		event.SetSummary(talk.Title)
		event.SetDescription(talk.Body)
		event.SetURL(talk.Link)

		// Write out as download
		contentDisposition := fmt.Sprintf("attachment; filename=\"tumevent%d.ics\"", talk.ID)
		w.Header().Set("Content-Disposition", contentDisposition)
		cal.SerializeTo(w)
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
		if talk == nil || err != nil {
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
			User     string
		}
		ctx := struct {
			baseCtx
			Talk ctxTalk
		}{
			router.baseCtx(w, r),
			ctxTalk{
				ID:       talk.ID,
				Title:    talk.Title,
				Date:     talk.Date,
				Category: talk.Category,
				Link:     talk.Link,
				Body:     template.HTML(talk.RenderAsHTML()),
				User:     talk.User,
			},
		}
		if err := router.templates["talk.html"].Execute(w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (router *Router) submitForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := router.baseCtx(w, r)
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}
		if !ac.Authenticated() {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Verify items one by one
		user := ac.Login
		// Title must at max contain 128 characters, and at least 10 non-whitespace ones
		title := strings.TrimSpace(r.Form.Get("title"))
		if !validateTitle(title) {
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
		if err := router.store.InsertTalk(talk); err != nil {
			logrus.WithError(err).Error("Failed to insert talk")
			http.Error(w, "inserting talk failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
			baseCtx
			Talks []*structs.Talk
		}{
			router.baseCtx(w, r),
			talks,
		}
		if err := router.templates["top.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
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
			baseCtx
			Talks []*structs.Talk
		}{
			router.baseCtx(w, r),
			talks,
		}
		if err := router.templates["top.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (router *Router) categories() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Put into top context
		context := struct {
			baseCtx
			Category   bool
			Categories []string
		}{
			router.baseCtx(w, r),
			false,
			talkCategories,
		}
		if err := router.templates["categories.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
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
			baseCtx
			Category string
			Talks    []*structs.Talk
		}{
			baseCtx:  router.baseCtx(w, r),
			Category: category,
			Talks:    talks,
		}
		if err := router.templates["categories.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (router *Router) apiTalks() http.Handler {
	type apiTalk struct {
		User     string    `json:"user"`
		Title    string    `json:"title"`
		Category string    `json:"category"`
		Date     time.Time `json:"date"`
		Link     string    `json:"link,omitempty"`
		Body     string    `json:"body,omitempty"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		talks, err := router.store.UpcomingTalks()
		if err != nil {
			logrus.WithError(err).Error("Failed to get upcoming talks")
			http.Error(w, "failed to get data", http.StatusInternalServerError)
			return
		}
		// Reconstruct as API talks
		apiTalks := make([]*apiTalk, len(talks))
		for i, t := range talks {
			apiTalks[i] = &apiTalk{
				User:     t.User,
				Title:    t.Title,
				Category: t.Category,
				Date:     t.Date,
				Link:     t.Link,
				Body:     t.Body,
			}
		}
		if err := json.NewEncoder(w).Encode(apiTalks); err != nil {
			logrus.WithError(err).Error("Failed to encode response")
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})
}

func NewRouter(publicURL *url.URL, store *structs.Store, auth auth.Provider, httpsOnly, publicDomainOnly bool) *Router {
	return &Router{
		mux:              mux.NewRouter(),
		publicURL:        publicURL,
		store:            store,
		httpsOnly:        httpsOnly,
		publicDomainOnly: publicDomainOnly,
		auth:             auth,
	}
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Make sure to redirect users to default domain
	if router.publicDomainOnly && router.publicURL.Host != r.Host {
		// Issue redirect
		http.Redirect(w, r, router.publicURL.String(), http.StatusSeeOther)
		logrus.WithFields(logrus.Fields{
			"path":     r.URL.Path,
			"method":   r.Method,
			"got":      r.Host,
			"expected": router.publicURL.Host,
		}).Info("Redirected request to public base URL")
		return
	}

	s := time.Now()
	router.mux.ServeHTTP(w, r)
	d := time.Since(s)

	logrus.WithFields(logrus.Fields{
		"duration": d,
		"path":     r.URL.Path,
		"method":   r.Method,
	}).Info("Served request")
}
