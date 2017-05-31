package database

import (
	"net/http"

	"github.com/qor/auth"
)

// DatabaseProvider provide login with database method
type DatabaseProvider struct {
}

// GetProviderName return provider name
func (DatabaseProvider) GetProviderName() string {
	return "database"
}

// Login implemented login with phone provider
func (DatabaseProvider) Login(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Logout implemented logout with phone provider
func (DatabaseProvider) Logout(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Register implemented register with phone provider
func (DatabaseProvider) Register(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}
