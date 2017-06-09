package database

import (
	"net/http"

	"github.com/qor/auth"
)

// New initialize database provider
func New() *DatabaseProvider {
	return &DatabaseProvider{}
}

// DatabaseProvider provide login with database method
type DatabaseProvider struct {
	Auth      *auth.Auth
	Authorize func(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) (interface{}, error)
}

// GetName return provider name
func (DatabaseProvider) GetName() string {
	return "database"
}

// ConfigAuth implemented ConfigAuth for database provider
func (provider DatabaseProvider) ConfigAuth(auth *auth.Auth) {
	provider.Auth = auth
}

// Login implemented login with database provider
func (provider DatabaseProvider) Login(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
	currentUser, err := provider.Authorize(request, writer, claims)
	if err == nil && currentUser != nil {
		provider.Auth.LoginHandler(request, writer, currentUser, claims)
	}
}

// Logout implemented logout with database provider
func (DatabaseProvider) Logout(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
	provider.Auth.LogoutHandler(request, writer, nil, claims)
}

// Register implemented register with database provider
func (DatabaseProvider) Register(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
	provider.Auth.RegisterHandler(request, writer, nil, claims)
}

// Callback implement Callback with database provider
func (DatabaseProvider) Callback(*http.Request, http.ResponseWriter, *auth.Claims) {
}

// ServeHTTP implement ServeHTTP with database provider
func (DatabaseProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Claims) {
}
