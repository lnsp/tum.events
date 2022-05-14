package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

//go:embed template/*
var content embed.FS

func main() {
	//	token := os.Getenv("VALAR_TOKEN")
	//	project := os.Getenv("VALAR_PROJECT")
	router := NewRouter()
	router.setup()
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		Handler:      router,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
}

type Router struct {
	mux *mux.Router

	templates map[string]*template.Template
}

func (router *Router) setup() {
	// setup routes
	router.mux.Handle("/", router.top()).Methods("GET")
	router.mux.Handle("/top", router.top()).Methods("GET")
	router.mux.Handle("/nextup", router.nextup()).Methods("GET")
	router.mux.Handle("/categories", router.categories()).Methods("GET")
	router.mux.Handle("/categories/{category}", router.category()).Methods("GET")
	router.mux.Handle("/submit", router.submit()).Methods("GET")
	router.mux.Handle("/submit", router.accept()).Methods("POST")
	// parse templates
	router.templates = make(map[string]*template.Template)
	for _, t := range []string{"template/categories.html", "template/next.html", "template/submit.html", "template/top.html"} {
		router.templates[path.Base(t)] = template.Must(template.New("base.html").Funcs(template.FuncMap{
			"humandate": func(t time.Time) string {
				return t.Format("02.01.2006 15:04")
			},
		}).ParseFS(content, "template/base.html", t))
	}
}

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

func (router *Router) submit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		context := struct{ Categories []string }{talkCategories}
		if err := router.templates["submit.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
		}
	})
}

func (router *Router) accept() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}

func (router *Router) top() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		context := struct {
			Talks []Talk
		}{
			FetchTalks(),
		}
		if err := router.templates["top.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
		}
	})
}

func (router *Router) nextup() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get talks sorted by date
		talks := FetchTalks()
		sort.Slice(talks, func(i, j int) bool { return talks[i].Date.Before(talks[j].Date) })

		// Put into top context
		context := struct {
			Talks []Talk
		}{
			talks,
		}
		if err := router.templates["top.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
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
		talks := FetchTalks()
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
			Talks    []Talk
		}{
			Category: category,
			Talks:    talks,
		}
		if err := router.templates["categories.html"].Execute(w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
		}
	})
}

func NewRouter() *Router {
	return &Router{
		mux: mux.NewRouter(),
	}
}
func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	router.mux.ServeHTTP(w, r)
}

type Talk struct {
	Rank      int
	Submitter string
	Title     string
	Category  string
	Date      time.Time
	Link      string
}

func FetchTalks() []Talk {
	return []Talk{
		{1, "ga87fey", "Test talk 1", "programming-languages", time.Now().Add(time.Hour * 24), "https://github.com"},
		{2, "ga87fey", "Test talk 2", "programming-languages", time.Now(), "https://github.com"},
	}
}

func fetch(token, project, key string) ([]Talk, error) {
	url := fmt.Sprintf("https://kv.valar.dev/%s/%s", project, key)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	talks := []Talk{}
	if err := json.Unmarshal(data, talks); err != nil {
		return nil, err
	}
	return talks, nil
}
