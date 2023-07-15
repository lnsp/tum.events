package auth

import (
	"net/http"

	"github.com/lnsp/tum.events/structs"
)

const cookieName = "session"

type Session struct {
	Storage   *structs.Storage
	HTTPSOnly bool
}

func (Session) Drop(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		MaxAge: -1,
	})
}

func (sc Session) Set(w http.ResponseWriter, session *structs.Session) {
	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    session.Key,
		Expires:  session.Expiration,
		Secure:   sc.HTTPSOnly,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (sc Session) Logout(w http.ResponseWriter, sessionKey string) error {
	sc.Drop(w)
	return sc.Storage.DeleteSession(sessionKey)
}

func (sc Session) Validate(w http.ResponseWriter, r *http.Request) (user string, key string, ok bool) {
	cookie, err := r.Cookie(cookieName)
	if err == http.ErrNoCookie {
		return
	}
	// Get session key from cookie
	key = cookie.Value
	// Make sure that key is valid session key
	if !LoginKeyRegex.MatchString(key) {
		sc.Drop(w)
		return
	}
	user, err = sc.Storage.VerifySession(key)
	if err != nil {
		// Delete session cookie
		sc.Drop(w)
		return
	}
	return user, key, true
}
