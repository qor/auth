package database

import (
	"html/template"
	"net/mail"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/mailer"
)

// ConfirmationMailSubject confirmation mail's subject
var ConfirmationMailSubject = "Please confirm your account"

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "confirm"

	var confirmURL url.URL
	if context.Request != nil && context.Request.URL != nil {
		confirmURL.Host = context.Request.URL.Host
		confirmURL.Scheme = context.Request.URL.Scheme
	}
	confirmURL.Path = path.Join(context.Auth.AuthURL("database/confirm"), context.Auth.SignedToken(claims))

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			Subject: ConfirmationMailSubject,
		}, mailer.Template{
			Name:    "auth/confirmation",
			Data:    context,
			Request: context.Request,
			Writer:  context.Writer,
		}.Funcs(template.FuncMap{
			"current_user": currentUser,
			"confirm_url":  confirmURL.String(),
		}),
	)
}

// DefaultConfirmHandler default confirm handler
var DefaultConfirmHandler = func(context *auth.Context) error {
	var (
		authInfo    auth_identity.Basic
		provider, _ = context.Provider.(*Provider)
		tx          = context.Auth.GetDB(context.Request)
		paths       = strings.Split(context.Request.URL.Path, "/")
		token       = paths[len(paths)-1]
	)

	claims, err := context.Auth.Validate(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			authInfo.Provider = provider.GetName()
			authInfo.UID = claims.Id

			if tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return auth.ErrInvalidAccount
			}

			now := time.Now()
			authInfo.ConfirmedAt = &now
			return tx.Model(context.Auth.AuthIdentityModel).Save(&authInfo).Error
		}
	}

	return err
}
