package database

import (
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strings"

	"html/template"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/mailer"
)

// ResetPasswordMailSubject reset password mail's subject
var ResetPasswordMailSubject = "Reset your password"

// DefaultResetPasswordMailer default reset password mailer
var DefaultResetPasswordMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "reset_password"

	var resetPasswordURL url.URL
	if context.Request != nil && context.Request.URL != nil {
		resetPasswordURL.Host = context.Request.URL.Host
		resetPasswordURL.Scheme = context.Request.URL.Scheme
	}
	resetPasswordURL.Path = path.Join(context.Auth.AuthURL("database/confirm"), context.Auth.SignedToken(claims))

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			Subject: ResetPasswordMailSubject,
		}, mailer.Template{
			Name:    "auth/reset_password",
			Data:    context,
			Request: context.Request,
			Writer:  context.Writer,
		}.Funcs(template.FuncMap{
			"current_user":       currentUser,
			"reset_password_url": resetPasswordURL.String(),
		}),
	)
}

// DefaultResetPasswordHandler default reset password handler
var DefaultResetPasswordHandler = func(context *auth.Context) error {
	var (
		authInfo    auth_identity.Basic
		email       = context.Request.Form.Get("email")
		provider, _ = context.Provider.(*Provider)
	)

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(email)

	currentUser, err := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)

	if err != nil {
		return err
	}

	err = provider.ResetPasswordMailer(email, context, authInfo.ToClaims(), currentUser)

	if err == nil {
		http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
	}
	return err
}
