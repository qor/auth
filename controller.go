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
	var (
		reqPath = strings.TrimPrefix(req.URL.Path, serveMux.Prefix)
		paths   = strings.Split(reqPath, "/")
		claims  *Claims
	)

	if len(paths) >= 2 {
		// eg: /phone/login

		if provider := serveMux.Auth.GetProvider(paths[0]); provider != nil {
			// serve mux
			switch paths[1] {
			case "login":
				provider.Login(req, w, claims)
			case "logout":
				provider.Logout(req, w, claims)
			case "register":
				provider.Register(req, w, claims)
			case "callback":
				provider.Callback(req, w, claims)
			default:
				provider.ServeHTTP(req, w, claims)
			}
			return
		}
	} else if len(paths) == 1 {
		// eg: /login, /logout

		switch paths[0] {
		case "login":
			// render login page
			serveMux.Auth.Render.Execute("auth/login", serveMux, req, w)
			return
		case "logout":
			// destroy login session
			return
		case "register":
			// render register page
			serveMux.Auth.Render.Execute("auth/register", serveMux, req, w)
			return
		}
	}

	http.NotFound(w, req)
}
