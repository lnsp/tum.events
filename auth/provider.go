package auth

import (
	"regexp"

	"github.com/lnsp/tumtalks/mail"
	"github.com/lnsp/tumtalks/structs"
	"github.com/sirupsen/logrus"
)

type Provider interface {
	Login(user string) (*structs.Login, error)
	LoginWithCode(key, code string) (*structs.Session, error)
}

type VerifiedProvider struct {
	Store *structs.Store
	Mail  mail.Provider
}

var userRegex = regexp.MustCompile(`^[a-z]{2}[0-9]{2}[a-z]{3}$`)

func (provider *VerifiedProvider) Login(user string) (*structs.Login, error) {
	if !userRegex.MatchString(user) {
		return nil, structs.ErrInvalidInput
	}

	// Check that there is no active login attempt
	active, timeout, err := provider.Store.HasTooManyLogins(user)
	if err != nil {
		logrus.WithError(err).Error("Failed to check login attempts")
		return nil, err
	}
	if active {
		return nil, &structs.TooManyLoginsError{Timeout: timeout}
	}

	// Create login attempt
	login, err := provider.Store.AttemptLogin(user)
	if err != nil {
		logrus.WithError(err).Error("Failed to create login")
		return nil, err
	}

	// Send out email
	if err := provider.Mail.SendLogin(login.User, login.Code); err != nil {
		logrus.WithError(err).Error("Failed to send login")
		return nil, err
	}

	return login, nil
}

func (provider *VerifiedProvider) LoginWithCode(key, code string) (*structs.Session, error) {
	session, _, err := provider.Store.ConfirmLogin(key, code)
	return session, err
}
