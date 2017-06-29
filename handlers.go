package auth

import (
	"net/http"

	"github.com/qor/auth/claims"
	"github.com/qor/responder"
	"github.com/qor/session/manager"
)

func respondAfterLogged(claims *claims.Claims, context *Context) {
	token := context.Auth.SignedToken(claims)

	// Set auth session
	manager.SessionManager.Add(context.Request, context.Auth.Config.SessionName, token)

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
		respondAfterLogged(claims, context)
		return
	}

	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/login", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
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

	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/register", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}

// DefaultLogoutHandler default logout behaviour
var DefaultLogoutHandler = func(context *Context) {
	// Clear auth session
	manager.SessionManager.Pop(context.Request, context.Auth.Config.SessionName)

	http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
}
