package auth

import (
	"net/http"

	"github.com/qor/auth/claims"
	"github.com/qor/responder"
	"github.com/qor/session"
)

func respondAfterLogged(claims *claims.Claims, context *Context) {
	// login user
	context.Auth.Login(claims, context.Request)

	responder.With("html", func() {
		// write cookie
		http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
	}).With([]string{"json"}, func() {
		// write json token
	}).Respond(context.Request)
}

// DefaultLoginHandler default login behaviour
var DefaultLoginHandler = func(context *Context, authorize func(*Context) (*claims.Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = authorize(context)
	)

	if err == nil && claims != nil {
		context.SessionStorer.Flash(req, session.Message{Message: "logged"})
		respondAfterLogged(claims, context)
		return
	}

	context.SessionStorer.Flash(req, session.Message{Message: err.Error(), Type: "error"})

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/login", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	}).Respond(context.Request)
}

// DefaultRegisterHandler default register behaviour
var DefaultRegisterHandler = func(context *Context, register func(*Context) (*claims.Claims, error)) {
	var (
		req         = context.Request
		w           = context.Writer
		claims, err = register(context)
	)

	if err == nil && claims != nil {
		respondAfterLogged(claims, context)
		return
	}

	context.SessionStorer.Flash(req, session.Message{Message: err.Error(), Type: "error"})

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/register", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	}).Respond(context.Request)
}

// DefaultLogoutHandler default logout behaviour
var DefaultLogoutHandler = func(context *Context) {
	// Clear auth session
	context.SessionStorer.Delete(context.Request)
	http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
}
