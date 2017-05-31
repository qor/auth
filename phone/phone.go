package phone

import (
	"net/http"

	"github.com/qor/auth"
)

func New() *PhoneProvider {
	return &PhoneProvider{}
}

// PhoneProvider provide login with phone method
type PhoneProvider struct {
}

// GetProviderName return provider name
func (PhoneProvider) GetProviderName() string {
	return "phone"
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
