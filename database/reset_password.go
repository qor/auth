package database

import (
	"net/mail"
	"net/url"
	"path"

	"html/template"

	"github.com/qor/auth"
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
