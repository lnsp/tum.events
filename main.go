package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/lnsp/tum.events/auth"
	"github.com/lnsp/tum.events/handlers"
	"github.com/lnsp/tum.events/kv"
	"github.com/lnsp/tum.events/mail"
	"github.com/lnsp/tum.events/structs"
	"github.com/lnsp/tum.events/templates"
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

	// Parse environment variables
	envspec := struct {
		Debug            bool   `envconfig:"DEBUG"`
		DebugDump        string `envconfig:"DEBUG_DUMP"`
		MailSender       string `envconfig:"MAIL_SENDER"`
		MailDomain       string `envconfig:"MAIL_DOMAIN"`
		MailAPIKey       string `envconfig:"MAIL_APIKEY"`
		MailUserDomain   string `envconfig:"MAIL_USERDOMAIN"`
		ValarToken       string `envconfig:"VALAR_TOKEN"`
		ValarProject     string `envconfig:"VALAR_PROJECT"`
		ValarPrefix      string `envconfig:"VALAR_PREFIX"`
		RouterHTTPSOnly  bool   `envconfig:"ROUTER_HTTPSONLY"`
		RouterPublicURL  string `envconfig:"ROUTER_PUBLICURL"`
		RouterDomainOnly bool   `envconfig:"ROUTER_DOMAINONLY"`
		RouterCSRFKey    string `envconfig:"ROUTER_CSRFKEY"`
	}{}
	if err := envconfig.Process("", &envspec); err != nil {
		logrus.WithError(err).Fatal("invalid envspec")
	}

	mailProvider := mail.Provider(&mail.DebugProvider{})
	if !envspec.Debug {
		mailProvider = mail.NewMailgunProvider(&mail.MailgunConfig{
			Sender:       envspec.MailSender,
			SenderDomain: envspec.MailDomain,
			APIKey:       envspec.MailAPIKey,
			UserDomain:   envspec.MailUserDomain,
		})
	}

	kvBackend := kv.NewInMemoryStore()
	if !envspec.Debug {
		kvBackend = kv.NewRemoteStore(kv.Credentials{
			Token:   envspec.ValarToken,
			Project: envspec.ValarProject,
		})
	}
	if envspec.DebugDump != "" {
		f, _ := os.Open(envspec.DebugDump)
		kv.RestoreFromDump(kvBackend, f)
		f.Close()
	}

	storage := structs.NewStorage(kvBackend, os.Getenv("VALAR_PREFIX"))
	authProvider := &auth.MailBasedAuth{
		Mail:    mailProvider,
		Storage: storage,
	}
	session := &auth.Session{
		Storage:   storage,
		HTTPSOnly: envspec.RouterHTTPSOnly,
	}

	publicURL, err := url.Parse(envspec.RouterPublicURL)
	if err != nil {
		logrus.WithError(err).Fatal("public url is invalid")
	}
	csrf := csrf.Protect(
		[]byte(os.Getenv("ROUTER_CSRFKEY")), csrf.Secure(!envspec.Debug))
	router := &Router{
		mux:              mux.NewRouter(),
		publicURL:        publicURL,
		storage:          storage,
		session:          session,
		publicDomainOnly: envspec.RouterDomainOnly,
		auth:             authProvider,
		middleware:       []mux.MiddlewareFunc{csrf},
	}
	router.setup()
	if envspec.Debug {
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

func (router *Router) setupDebugRoutes(kvstore kv.Store) {
	router.mux.HandleFunc("/debug/dump", func(wr http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			if err := kv.WriteToDump(kvstore, wr); err != nil {
				logrus.WithError(err).Error("could not write to dump")
				return
			}
			wr.WriteHeader(http.StatusOK)
		case http.MethodPost:
			if err := kv.RestoreFromDump(kvstore, req.Body); err != nil {
				logrus.WithError(err).Error("could not restore from dump")
				return
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
	userHandler := &handlers.User{
		Context: router.baseCtx,
		Auth:    router.auth,
		Session: router.session,
		Storage: router.storage,
	}
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
