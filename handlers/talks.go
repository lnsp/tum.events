package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	ics "github.com/arran4/golang-ical"
	"github.com/gorilla/mux"
	"github.com/lnsp/tumtalks/structs"
	"github.com/lnsp/tumtalks/templates"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

const localTimeFormat = "2006-01-02T15:04"

type Talks struct {
	Context templates.ContextFunc
	Storage *structs.Storage
}

func (h Talks) Setup(router *mux.Router) {
	router.Handle("/", h.top()).Methods("GET")
	router.Handle("/top", h.top()).Methods("GET")
	router.Handle("/nextup", h.nextup()).Methods("GET")
	router.Handle("/filter", h.filter()).Methods("GET")
	router.Handle("/categories", h.categories()).Methods("GET")
	router.Handle("/talk", h.downloadTalk()).Methods("GET").Queries("id", "{id:[0-9]+}", "format", "ics")
	router.Handle("/talk", h.talk()).Methods("GET").Queries("id", "{id:[0-9]+}")
	router.Handle("/edit", h.edit()).Methods("GET").Queries("id", "{id:[0-9]+}")
	router.Handle("/edit", h.editForm()).Methods("POST").Queries("id", "{id:[0-9]+}")
	router.Handle("/submit", h.submit()).Methods("GET")
	router.Handle("/submit", h.submitForm()).Methods("POST")
	router.Handle("/verify/{secret}", h.confirm()).Methods("GET")
	router.Handle("/verify/{secret}", h.verify()).Methods("POST")
}

func (h Talks) submit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := h.Context(w, r)
		if !ac.Authenticated() {
			// Redirect to login form
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		context := struct {
			templates.Context
			Categories []string
		}{ac, structs.TalkCategories}

		if err := templates.Execute("submit.html", w, &context); err != nil {
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

func (h Talks) confirm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := h.Context(w, r)
		if err := templates.Execute("confirm.html", w, &struct {
			templates.Context
			Talk bool
		}{ac, true}); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h Talks) verify() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := mux.Vars(r)["secret"]
		if err := h.Storage.Verify(secret); err != nil {
			http.Error(w, "could not verify talk", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (h Talks) edit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idstr := mux.Vars(r)["id"]
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			http.Error(w, "bad id format", http.StatusBadRequest)
			return
		}
		ac := h.Context(w, r)
		if !ac.Authenticated() {
			http.Redirect(w, r, "/talk?id="+idstr, http.StatusSeeOther)
			return
		}
		// Get post with given ID
		talk, err := h.Storage.Talk(id)
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
			templates.Context
			Talk       *structs.Talk
			Categories []string
		}{
			Context:    ac,
			Talk:       talk,
			Categories: structs.TalkCategories,
		}
		if err := templates.Execute("edit.html", w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h Talks) editForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idstr := mux.Vars(r)["id"]
		id, err := strconv.ParseInt(idstr, 10, 64)
		if err != nil {
			http.Error(w, "bad id format", http.StatusBadRequest)
			return
		}
		ac := h.Context(w, r)
		if !ac.Authenticated() {
			http.Redirect(w, r, "/talk?id="+idstr, http.StatusSeeOther)
			return
		}
		// Get post with given ID
		talk, err := h.Storage.Talk(id)
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
				templates.Context
				Talk       *structs.Talk
				Categories []string
			}{
				Context:    ac,
				Talk:       talk,
				Categories: structs.TalkCategories,
			}
			ctx.Error = errorMsg
			if err := templates.Execute("edit.html", w, &ctx); err != nil {
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
			if err := h.Storage.DeleteTalk(id); err != nil {
				showError("Failed to delete talk. Please try again later.", http.StatusInternalServerError)
				logrus.WithError(err).Error("Failed to delete talk")
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
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
		if !slices.Contains(structs.TalkCategories, category) {
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
		if err := h.Storage.UpdateTalk(talk); err != nil {
			showError(genericErrorMessage, http.StatusInternalServerError)
			logrus.WithError(err).Error("Failed to update talk")
			return
		}
		// Redirect to talk page
		http.Redirect(w, r, "/talk?id="+idstr, http.StatusSeeOther)
	})
}

func (h Talks) downloadTalk() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
		if err != nil {
			http.Error(w, "invalid talk id", http.StatusBadRequest)
			return
		}
		talk, err := h.Storage.Talk(id)
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

func (h Talks) talk() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
		if err != nil {
			http.Error(w, "invalid talk id", http.StatusBadRequest)
			return
		}
		talk, err := h.Storage.Talk(id)
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
			templates.Context
			Talk ctxTalk
		}{
			h.Context(w, r),
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
		if err := templates.Execute("talk.html", w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h Talks) submitForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := h.Context(w, r)
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
		if !slices.Contains(structs.TalkCategories, category) {
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
		if err := h.Storage.InsertTalk(talk); err != nil {
			logrus.WithError(err).Error("Failed to insert talk")
			http.Error(w, "inserting talk failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (h Talks) top() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		talks, err := h.Storage.UpcomingTalks()
		if err != nil {
			http.Error(w, "could not retrieve talks", http.StatusInternalServerError)
			return
		}
		sort.Slice(talks, func(i, j int) bool { return talks[i].Rank < talks[j].Rank })

		context := struct {
			templates.Context
			Talks []*structs.Talk
		}{
			h.Context(w, r),
			talks,
		}
		if err := templates.Execute("top.html", w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h Talks) nextup() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get talks sorted by date
		talks, err := h.Storage.UpcomingTalks()
		if err != nil {
			http.Error(w, "could not retrieve talks", http.StatusInternalServerError)
			return
		}
		sort.Slice(talks, func(i, j int) bool { return talks[i].Date.Before(talks[j].Date) })

		// Put into top context
		context := struct {
			templates.Context
			Talks []*structs.Talk
		}{
			h.Context(w, r),
			talks,
		}
		if err := templates.Execute("top.html", w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h Talks) categories() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Put into top context
		context := struct {
			templates.Context
			Category   bool
			Categories []string
		}{
			h.Context(w, r),
			false,
			structs.TalkCategories,
		}
		if err := templates.Execute("categories.html", w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h Talks) filter() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get category or site filter
		query := r.URL.Query()
		site := query.Get("site")
		category := query.Get("category")
		filters := make([]func(t *structs.Talk) bool, 0, 2)
		// Check that category is in 'valid' categories
		if category != "" {
			if !slices.Contains(structs.TalkCategories, category) {
				http.Error(w, "category not found", http.StatusNotFound)
				return
			}
			filters = append(filters, func(t *structs.Talk) bool {
				return t.Category == category
			})
		}
		// Add site filter
		if site != "" {
			filters = append(filters, func(t *structs.Talk) bool {
				return t.LinkDomain == site
			})
		}
		// Put into top context
		talks, err := h.Storage.UpcomingTalks()
		if err != nil {
			http.Error(w, "could not retrieve talks", http.StatusInternalServerError)
			return
		}
		// Filter talks
		j := 0
		for i := range talks {
			match := true
			for j := range filters {
				if !filters[j](talks[i]) {
					match = false
					break
				}
			}
			if match {
				talks[j] = talks[i]
				j++
			}
		}
		talks = talks[:j]
		// Sort by date
		sort.Slice(talks, func(i, j int) bool { return talks[i].Date.Before(talks[j].Date) })

		context := struct {
			templates.Context
			Category   string
			LinkDomain string
			Talks      []*structs.Talk
		}{
			Context:    h.Context(w, r),
			Category:   category,
			LinkDomain: site,
			Talks:      talks,
		}
		if err := templates.Execute("filter.html", w, &context); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}
