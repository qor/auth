package password

import (
	"errors"
	"html/template"
	"net/mail"
	"path"
	"reflect"
	"time"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/mailer"
	"github.com/qor/qor/utils"
	"github.com/qor/session"
)

var (
	// ConfirmationMailSubject confirmation mail's subject
	ConfirmationMailSubject = "Please confirm your account"

	// ConfirmedAccountFlashMessage confirmed your account message
	ConfirmedAccountFlashMessage = template.HTML("Confirmed your account!")

	// ConfirmFlashMessage confirm account flash message
	ConfirmFlashMessage = template.HTML("Please confirm your account")

	// ErrAlreadyConfirmed account already confirmed error
	ErrAlreadyConfirmed = errors.New("Your account already been confirmed")

	// ErrUnconfirmed unauthorized error
	ErrUnconfirmed = errors.New("You have to confirm your account before continuing")
)

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "confirm"

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			From:    &mail.Address{Address: "info@77g.de"},
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
				confirmURL.Path = path.Join(context.Auth.AuthURL("password/confirm"))
				qry := confirmURL.Query()
				qry.Set("token", context.SessionStorer.SignedToken(claims))
				confirmURL.RawQuery = qry.Encode()
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
		token       = context.Request.URL.Query().Get("token")
		currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
	)

	claims, err := context.SessionStorer.ValidateClaims(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			authInfo.Provider = provider.GetName()
			authInfo.UID = claims.Id
			authInfo.UserID = claims.UserID
			authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
			authwhere := auth_identity.AuthIdentity{Basic: authInfo}

			if tx.Where(authwhere).First(authIdentity).RecordNotFound() {
				err = auth.ErrInvalidAccount
				return err
			}
			//load user to get ConfirmedAt date
			tx.Where(&authwhere).First(&authwhere)

			if err == nil {
				if authwhere.Basic.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now

					//User updaten
					tx.Model(&currentUser).Where("ID = ? and email = ?", authwhere.Basic.UserID, authwhere.Basic.UID).Updates(map[string]interface{}{"confirm_token": token, "confirmed": true})

					if err = tx.Model(authwhere).Where("user_id = ?", authInfo.UserID).Update(authInfo).Error; err == nil {
						context.SessionStorer.Flash(context.Writer, context.Request, session.Message{Message: ConfirmedAccountFlashMessage, Type: "success"})
						context.Auth.Redirector.Redirect(context.Writer, context.Request, "confirm")
						return nil
					}
				}
				err = ErrAlreadyConfirmed
			}
		}
	}

	return err
}
