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

// GetName return provider name
func (PhoneProvider) GetName() string {
	return "phone"
}

// ConfigAuth implemented ConfigAuth for phone provider
func (PhoneProvider) ConfigAuth(*auth.Auth) {
}

// Login implemented login with phone provider
func (PhoneProvider) Login(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Logout implemented logout with phone provider
func (PhoneProvider) Logout(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Register implemented register with phone provider
func (PhoneProvider) Register(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Callback implement Callback with phone provider
func (PhoneProvider) Callback(*http.Request, http.ResponseWriter, *auth.Session) {
}

// ServeHTTP implement ServeHTTP with phone provider
func (PhoneProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Session) {
}
