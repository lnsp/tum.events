package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/lnsp/tum.events/structs"
	"github.com/sirupsen/logrus"
)

type API struct {
	Storage *structs.Storage
}

func (h API) Setup(router *mux.Router) {
	router.Handle("/talks", h.talks()).Methods("GET")
}

func (h API) talks() http.Handler {
	type apiTalk struct {
		User     string    `json:"user"`
		Title    string    `json:"title"`
		Category string    `json:"category"`
		Date     time.Time `json:"date"`
		Link     string    `json:"link,omitempty"`
		Body     string    `json:"body,omitempty"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		talks, err := h.Storage.UpcomingTalks()
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
