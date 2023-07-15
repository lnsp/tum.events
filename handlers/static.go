package handlers

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lnsp/tum.events/templates"
	"github.com/sirupsen/logrus"
)

type Static struct {
	Context templates.ContextFunc
}

func (h Static) Setup(router *mux.Router) {
	router.Handle("/styles.css", h.styles()).Methods("GET")
	router.Handle("/favicon.png", h.favicon()).Methods("GET")
	router.Handle("/legal", h.legal()).Methods("GET")
}

func (Static) styles() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(templates.TailwindStyles)
	})
}

func (Static) favicon() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(templates.Favicon)
	})
}

func (h Static) legal() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := templates.Execute("legal.html", w, h.Context(w, r)); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}
