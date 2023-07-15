package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/lnsp/tumtalks/auth"
	"github.com/lnsp/tumtalks/handlers"
	"github.com/lnsp/tumtalks/kv"
	"github.com/lnsp/tumtalks/mail"
	"github.com/lnsp/tumtalks/structs"
	"github.com/lnsp/tumtalks/templates"
	"github.com/sirupsen/logrus"

	_ "embed"
	_ "time/tzdata"
)

//go:generate sh -c "/bin/echo -n $VALAR_BUILD | head -c 8 > version.txt"
//go:embed version.txt
var buildID string

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

	kvBackend := kv.NewInMemoryStore()
	if !debugMode {
		kvBackend = kv.NewRemoteStore(kv.Credentials{
			Token:   os.Getenv("VALAR_TOKEN"),
			Project: os.Getenv("VALAR_PROJECT"),
		})
	}

	storage := structs.NewStorage(kvBackend, os.Getenv("VALAR_PREFIX"))
	authProvider := &auth.MailBasedAuth{
		Mail:    mailProvider,
		Storage: storage,
	}
	session := &auth.Session{
		Storage:   storage,
		HTTPSOnly: os.Getenv("ROUTER_HTTPSONLY") != "",
	}

	publicURL, err := url.Parse(os.Getenv("ROUTER_PUBLICURL"))
	if err != nil {
		logrus.WithError(err).Fatal("public url is invalid")
	}
	publicDomainOnly := os.Getenv("ROUTER_DOMAINONLY") != ""
	csrf := csrf.Protect(
		[]byte(os.Getenv("ROUTER_CSRFKEY")), csrf.Secure(!debugMode))
	router := &Router{
		mux:              mux.NewRouter(),
		publicURL:        publicURL,
		storage:          storage,
		session:          session,
		publicDomainOnly: publicDomainOnly,
		auth:             authProvider,
		middleware:       []mux.MiddlewareFunc{csrf},
	}
	router.setup()
	if debugMode {
		router.setupDebugRoutes(kvBackend)
	}
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

type Router struct {
	publicURL        *url.URL
	mux              *mux.Router
	storage          *structs.Storage
	publicDomainOnly bool
	auth             auth.Auth
	session          *auth.Session
	middleware       []mux.MiddlewareFunc
}

func (router *Router) setupDebugRoutes(kv kv.Store) {
	router.mux.HandleFunc("/debug/dump", func(wr http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			keys, _, err := kv.List("")
			if err != nil {
				http.Error(wr, err.Error(), http.StatusInternalServerError)
				return
			}
			kvs := map[string]string{}
			for _, key := range keys {
				value, err := kv.Fetch(key)
				if err != nil {
					http.Error(wr, err.Error(), http.StatusInternalServerError)
					return
				}
				kvs[key] = string(value)
			}
			if err := json.NewEncoder(wr).Encode(kvs); err != nil {
				http.Error(wr, err.Error(), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
			kvs := map[string]string{}
			if err := json.NewDecoder(req.Body).Decode(&kvs); err != nil {
				http.Error(wr, err.Error(), http.StatusInternalServerError)
				return
			}
			for key, value := range kvs {
				if err := kv.Put(key, []byte(value)); err != nil {
					http.Error(wr, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			wr.WriteHeader(http.StatusOK)
		}
	}).Methods("GET", "POST")
}

func (router *Router) setup() {
	// setup routes
	frontend := router.mux.PathPrefix("/").Subrouter()
	for _, mw := range router.middleware {
		frontend.Use(mw)
	}

	// setup talk routes
	talksHandler := &handlers.Talks{Context: router.baseCtx, Storage: router.storage}
	talksHandler.Setup(frontend)

	// setup user session routes
	userHandler := &handlers.User{Context: router.baseCtx, Auth: router.auth, Session: router.session}
	userHandler.Setup(frontend)

	// setup static routes
	staticHandler := &handlers.Static{Context: router.baseCtx}
	staticHandler.Setup(frontend)

	// setup api routes
	apiHandler := &handlers.API{Storage: router.storage}
	apiHandler.Setup(router.mux.PathPrefix("/api").Subrouter())

}

func (router *Router) baseCtx(w http.ResponseWriter, r *http.Request) templates.Context {
	ctx := templates.Context{Build: buildID, CSRFToken: csrf.TemplateField(r)}
	// Get request session cookie
	user, key, ok := router.session.Validate(w, r)
	if !ok {
		return ctx
	}
	ctx.Login = user
	ctx.SessionKey = key
	return ctx
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
