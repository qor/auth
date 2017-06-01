package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// NewServeMux generate http.Handler for auth
func (auth *Auth) NewServeMux(prefix string) http.Handler {
	prefix = fmt.Sprintf("/%v/", strings.Trim(prefix, "/"))
	return &serveMux{Auth: auth, Prefix: prefix}
}

type serveMux struct {
	Auth   *Auth
	Prefix string
}

// ServeHTTP dispatches the handler registered in the matched route
func (serveMux *serveMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	reqPath := strings.TrimPrefix(req.URL.Path, serveMux.Prefix)
	paths := strings.Split(reqPath, "/")

	if len(paths) >= 2 {
		// eg: /phone/login

		if provider := serveMux.Auth.GetProvider(paths[0]); provider != nil {
			// serve mux
		}
	} else if len(paths) == 0 {
		// eg: /login, /logout

		switch paths[0] {
		case "login":

		case "logout":

		case "register":
		}
	}
}
