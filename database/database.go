package database

import (
	"net/http"

	"github.com/qor/auth"
)

func New() *DatabaseProvider {
	return &DatabaseProvider{}
}

// DatabaseProvider provide login with database method
type DatabaseProvider struct {
}

// GetName return provider name
func (DatabaseProvider) GetName() string {
	return "database"
}

// ConfigAuth implemented ConfigAuth for database provider
func (DatabaseProvider) ConfigAuth(*auth.Auth) {
}

// Login implemented login with database provider
func (DatabaseProvider) Login(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Logout implemented logout with database provider
func (DatabaseProvider) Logout(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Register implemented register with database provider
func (DatabaseProvider) Register(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Callback implement Callback with database provider
func (DatabaseProvider) Callback(*http.Request, http.ResponseWriter, *auth.Claims) {
}

// ServeHTTP implement ServeHTTP with database provider
func (DatabaseProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Claims) {
}
