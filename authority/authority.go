package authority

import (
	"net/http"

	"github.com/qor/auth"
	"github.com/qor/auth/claims"
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
	GetCurrentUser(req *http.Request) interface{}
	GetClaims(req *http.Request) (*claims.Claims, error)
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

			if Auth, ok := authority.Auth.(*auth.Auth); ok {
				Auth.SessionManager.Flash(req, session.Message{Message: AccessDeniedFlashMessage})
				http.Redirect(w, req, Auth.AuthURL("login"), http.StatusSeeOther)
				return
			}

			http.Redirect(w, req, "/", http.StatusSeeOther)
		})
	}
}
