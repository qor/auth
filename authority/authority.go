package authority

import (
	"net/http"

	"github.com/qor/auth"
	"github.com/qor/roles"
	"github.com/qor/session"
)

var (
	// AccessDeniedFlashMessage access denied message
	AccessDeniedFlashMessage = "Access Denied!"
)

// Authority authority struct
type Authority struct {
	*Config
}

// AuthInterface auth interface
type AuthInterface interface {
	auth.SessionStorerInterface
	GetCurrentUser(req *http.Request) interface{}
}

// Config authority config
type Config struct {
	Auth AuthInterface
	Role *roles.Role
}

// New initialize Authority
func New(config *Config) *Authority {
	if config == nil {
		config = &Config{}
	}

	if config.Auth == nil {
		panic("Auth should not be nil for Authority")
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
			var currentUser interface{}

			// Get current user from request
			currentUser = authority.Auth.GetCurrentUser(req)

			if authority.Role.HasRole(req, currentUser, roles...) {
				handler.ServeHTTP(w, req)
				return
			}

			authority.Auth.Flash(req, session.Message{Message: AccessDeniedFlashMessage})
			authority.Auth.Redirect(w, req, "access_denied")
		})
	}
}
