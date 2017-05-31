package twitter

import (
	"net/http"

	"github.com/qor/auth"
)

// twitterProvider provide login with twitter method
type TwitterProvider struct {
}

// GetProviderName return provider name
func (TwitterProvider) GetProviderName() string {
	return "twitter"
}

// Login implemented login with twitter provider
func (TwitterProvider) Login(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Logout implemented logout with twitter provider
func (TwitterProvider) Logout(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}

// Register implemented register with twitter provider
func (TwitterProvider) Register(request *http.Request, writer http.ResponseWriter, claims *auth.Claims) {
}
