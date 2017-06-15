package auth

import (
	"fmt"
	"net/http"

	"github.com/qor/qor"
	"github.com/qor/qor/utils"
	"github.com/qor/responder"
)

// DefaultLoginHandler default login behaviour
var DefaultLoginHandler = func(req *http.Request, w http.ResponseWriter, session *Session, authorize func(*http.Request, http.ResponseWriter, *Session) (interface{}, error)) {
	tx := session.Auth.GetDB(req)
	currentUser, err := authorize(req, w, session)
	if err == nil {
		if currentUser != nil {
			claims := &Claims{}
			claims.Id = fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue())
			token := session.Auth.SignedToken(claims)
			context := &qor.Context{
				Request: req,
				Writer:  w,
			}

			utils.SetCookie(http.Cookie{
				Name:  session.Auth.Config.SessionName,
				Value: token,
			}, context)

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
		session.Auth.Config.Render.Execute("auth/login", session, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}

// DefaultRegisterHandler default register behaviour
var DefaultRegisterHandler = func(req *http.Request, w http.ResponseWriter, session *Session, register func(*http.Request, http.ResponseWriter, *Session) (interface{}, error)) {
	user, err := register(req, w, session)
	if err == nil {
		if user != nil {
			// registered
			http.Redirect(w, req, "/", http.StatusSeeOther)
		}
	}

	responder.With("html", func() {
		session.Auth.Config.Render.Execute("auth/register", session, req, w)
	}).With([]string{"json"}, func() {
		// write json error
	})
}
