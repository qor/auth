package auth

import (
	"fmt"
	"net/http"
)

// DefaultLoginHandler default behaviour after logged in
var DefaultLoginHandler = func(req *http.Request, w http.ResponseWriter, session *Session, authorize func(*http.Request, http.ResponseWriter, *Session) (interface{}, error)) {
	currentUser, err := authorize(req, w, session)
	if err == nil {
		if currentUser != nil {
			// write cookie, json
		} else {
		}
	}

	fmt.Println("cccc")
	session.Auth.Config.Render.Execute("auth/login", session, req, w)
}
