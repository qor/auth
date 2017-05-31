package phone

	GetCurrentUser(*http.Request, http.ResponseWriter, *Claims) interface{}
	DestroyCurrentSession(*http.Request, http.ResponseWriter, *Claims) error

import (
	"net/http"

	"github.com/qor/auth"
)

// PhoneProvider provide login with phone method
type PhoneProvider struct {
}

// Login implemented login with phone provider
func (PhoneProvider) Login(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Logout implemented logout with phone provider
func (PhoneProvider) Logout(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Register implemented register with phone provider
func (PhoneProvider) Register(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}
