package database

import (
	"html/template"
	"net/mail"

	"github.com/qor/auth"
	"github.com/qor/mailer"
)

// ConfirmationMailSubject confirmation mail's subject
var ConfirmationMailSubject = "Please confirm your account"

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, context *auth.Context, currentUser interface{}) error {
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
		}),
	)
}
