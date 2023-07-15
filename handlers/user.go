package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lnsp/tumtalks/auth"
	"github.com/lnsp/tumtalks/structs"
	"github.com/lnsp/tumtalks/templates"
	"github.com/sirupsen/logrus"
)

type User struct {
	Context templates.ContextFunc
	Auth    auth.Auth
	Session *auth.Session
}

const genericErrorMessage = "Something has gone awry. Please try again."

func (h User) Setup(router *mux.Router) {
	router.Handle("/login", h.loginWithCode()).Methods("POST").Queries("method", "code")
	router.Handle("/login", h.login()).Methods("GET")
	router.Handle("/login", h.loginForm()).Methods("POST")
	router.Handle("/logout", h.logout()).Methods("POST")
}

func (h User) login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := h.Context(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		ctx := struct {
			templates.Context
			Error string
		}{
			Context: ac,
		}
		// Else show login form
		if err := templates.Execute("login.html", w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}

func (h User) loginWithCode() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := h.Context(w, r)
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
				templates.Context
				Key string
			}{
				Context: ac,
				Key:     key,
			}
			ctx.Error = errorMsg
			if err := templates.Execute("login-code.html", w, &ctx); err != nil {
				logrus.WithError(err).Error("Failed to execute template")
				return
			}
		}
		if !auth.LoginKeyRegex.MatchString(key) {
			showError("Your login key is invalid. Please try again.")
			return
		}
		code := r.Form.Get("code")
		if !auth.LoginCodeRegex.MatchString(code) {
			showError("Your code is in the wrong format. Please try again.")
			return
		}
		// Retrieve login attempt with key
		session, err := h.Auth.LoginWithCode(key, code)
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
		h.Session.Set(w, session)
		// Redirect to home site
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (h User) logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is valid, else redirect to homepage
		ac := h.Context(w, r)
		if !ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		// Delete session from store
		h.Session.Logout(w, ac.SessionKey)
		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (h User) loginForm() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session is already valid, then redirect back to home page
		ac := h.Context(w, r)
		if ac.Authenticated() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		showError := func(errorMsg string, status int) {
			ac.Error = errorMsg
			// Else show login form
			w.WriteHeader(status)
			if err := templates.Execute("login.html", w, &ac); err != nil {
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
		login, err := h.Auth.Login(user)
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
			templates.Context
			Key string
		}{
			Context: ac,
			Key:     login.Key,
		}
		if err := templates.Execute("login-code.html", w, &ctx); err != nil {
			logrus.WithError(err).Error("Failed to execute template")
			return
		}
	})
}
