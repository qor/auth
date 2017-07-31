package password

import (
	"errors"
	"html/template"
	"net/http"
	"net/mail"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/mailer"
	"github.com/qor/qor/utils"
	"github.com/qor/session"
)

// ConfirmationMailSubject confirmation mail's subject
var ConfirmationMailSubject = "Please confirm your account"

// ErrAlreadyConfirmed account already confirmed error
var ErrAlreadyConfirmed = errors.New("Your account already been confirmed")

// ConfirmedAccountFlashMessage confirmed your account message
var ConfirmedAccountFlashMessage = "Confirmed your account!"

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "confirm"

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
			"current_user": func() interface{} {
				return currentUser
			},
			"confirm_url": func() string {
				confirmURL := utils.GetAbsURL(context.Request)
				confirmURL.Path = path.Join(context.Auth.AuthURL("password/confirm"), context.Auth.SignedToken(claims))
				return confirmURL.String()
			},
		}))
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
			authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()

			if tx.Where(authInfo).First(authIdentity).RecordNotFound() {
				err = auth.ErrInvalidAccount
			}

			if err == nil {
				if authInfo.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now
					if err = tx.Model(authIdentity).Update(authInfo).Error; err == nil {
						context.SessionManager.Flash(context.Request, session.Message{Message: ConfirmedAccountFlashMessage, Type: "success"})
						http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
						return nil
					}
				}
				err = ErrAlreadyConfirmed
			}
		}
	}

	return err
}
