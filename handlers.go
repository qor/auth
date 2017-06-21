package auth

import (
	"fmt"
	"net/http"

	"github.com/qor/qor"
	"github.com/qor/qor/utils"
	"github.com/qor/responder"
)

// DefaultLoginHandler default login behaviour
var DefaultLoginHandler = func(context *Context, authorize func(*Context) (interface{}, error)) {
	var (
		req              = context.Request
		w                = context.Writer
		tx               = context.Auth.GetDB(req)
		currentUser, err = authorize(context)
	)

	if err == nil {
		if currentUser != nil {
			claims := &Claims{}
			claims.Id = fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue())
			token := context.Auth.SignedToken(claims)
			qorContext := &qor.Context{
				Request: req,
				Writer:  w,
			}

			utils.SetCookie(http.Cookie{
				Name:  context.Auth.Config.SessionName,
				Value: token,
			}, qorContext)

			responder.With("html", func() {
				// write cookie
				fmt.Println(token)
				http.Redirect(w, req, "/", http.StatusSeeOther)
			}).With([]string{"json"}, func() {
				// write json token
				fmt.Println(token)
			}).Respond(req)
		}
	}

	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/login", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}

// DefaultRegisterHandler default register behaviour
var DefaultRegisterHandler = func(context *Context, register func(*Context) (interface{}, error)) {
	var (
		req       = context.Request
		w         = context.Writer
		user, err = register(context)
	)

	if err == nil {
		if user != nil {
			// registered
			http.Redirect(w, req, "/", http.StatusSeeOther)
		}
	}

	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/register", context, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}

// DefaultLogoutHandler default logout behaviour
var DefaultLogoutHandler = func(context *Context) {
	qorContext := &qor.Context{
		Request: context.Request,
		Writer:  context.Writer,
	}

	utils.SetCookie(http.Cookie{Name: context.Auth.Config.SessionName, Value: ""}, qorContext)
	http.Redirect(context.Writer, context.Request, "/", http.StatusSeeOther)
}
