package authority

import (
	"context"
	"net/http"

	"github.com/qor/auth"
	"github.com/qor/roles"
)

// Authority authority struct
type Authority struct {
	*Config
}

// Config authority config
type Config struct {
	Auth *auth.Auth
	Role *roles.Role
}

// New initialize Authority
func New(config *Config) *Authority {
	if config == nil {
		config = &Config{}
	}

	if config.Role == nil {
		config.Role = roles.Global
	}

	return &Authority{Config: config}
}

// Restrict restrict middleware
func (authority *Authority) Restrict(roles ...string) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Get current user from Header
			var currentUser = authority.Auth.GetCurrentUser(req)

			// get current user
			if currentUser != nil {
				req.WithContext(context.WithValue(req.Context(), auth.CurrentUser, currentUser))
			}

			if authority.Role.HasRole(req, currentUser, roles...) {
				handler.ServeHTTP(w, req)
			} else {
				http.Redirect(w, req, authority.Auth.AuthURL("login"), http.StatusSeeOther)
			}
		})
	}
}
