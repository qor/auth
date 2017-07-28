package confirmable

import (
	"html/template"
	"net/mail"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/password"
	"github.com/qor/mailer"
	"github.com/qor/qor/utils"
)

// Config confirmable's config
type Config struct {
	MailSubject      string
	ConfirmedMessage string

	MailSender func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error
}

// Confirmable confirmable struct
type Confirmable struct {
	*Config
}

// New initailize confirmable
func New(config *Config) *Confirmable {
	if config == nil {
		config = &Config{}
	}

	if config.MailSubject == "" {
		config.MailSubject = "Please confirm your account"
	}

	if config.ConfirmedMessage == "" {
		config.ConfirmedMessage = "Confirmed your account!"
	}

	if config.MailSender == nil {
		config.MailSender = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
			claims.Subject = "confirm"

			return context.Auth.Mailer.Send(
				mailer.Email{
					TO:      []mail.Address{{Address: email}},
					Subject: config.MailSubject,
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
						confirmURL.Path = path.Join(context.Auth.AuthURL("database/confirm"), context.Auth.SignedToken(claims))
						return confirmURL.String()
					},
				}))
		}
	}

	return &Confirmable{Config: config}
}

// GetName get hook's name
func (Confirmable) GetName() string {
	return "trackable"
}

// RegisterHooks register hooks
func (Confirmable) RegisterHooks(hooks *auth.Hooks) {
	hooks.After("*", auth.Hook{
		Name: "confirmable",
		Handle: func(context *auth.Context) error {
			return nil
		},
	})
}

// DefaultConfirmHandler default confirm handler
var DefaultConfirmHandler = func(context *auth.Context) error {
	var (
		authInfo    auth_identity.Basic
		provider, _ = context.Provider.(*password.Provider)
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
				return auth.ErrInvalidAccount
			}

			now := time.Now()
			authInfo.ConfirmedAt = &now
			return tx.Model(authIdentity).Update(authInfo).Error
		}
	}

	return err
}
