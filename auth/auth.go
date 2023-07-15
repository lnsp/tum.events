package auth

import (
	"regexp"

	"github.com/lnsp/tum.events/mail"
	"github.com/lnsp/tum.events/structs"
	"github.com/sirupsen/logrus"
)

type Auth interface {
	Login(user string) (*structs.Login, error)
	LoginWithCode(key, code string) (*structs.Session, error)
}

type MailBasedAuth struct {
	Storage *structs.Storage
	Mail    mail.Provider
}

var userRegex = regexp.MustCompile(`^[a-z]{2}[0-9]{2}[a-z]{3}$`)

func (provider *MailBasedAuth) Login(user string) (*structs.Login, error) {
	if !userRegex.MatchString(user) {
		return nil, structs.ErrInvalidInput
	}

	// Check that there is no active login attempt
	active, timeout, err := provider.Storage.HasTooManyLogins(user)
	if err != nil {
		logrus.WithError(err).Error("Failed to check login attempts")
		return nil, err
	}
	if active {
		return nil, &structs.TooManyLoginsError{Timeout: timeout}
	}

	// Create login attempt
	login, err := provider.Storage.AttemptLogin(user)
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

func (provider *MailBasedAuth) LoginWithCode(key, code string) (*structs.Session, error) {
	session, _, err := provider.Storage.ConfirmLogin(key, code)
	return session, err
}
