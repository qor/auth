package twitter

import (
	"net/http"

	"github.com/qor/auth"
)

func New() *TwitterProvider {
	return &TwitterProvider{}
}

// twitterProvider provide login with twitter method
type TwitterProvider struct {
}

// GetName return provider name
func (TwitterProvider) GetName() string {
	return "twitter"
}

// ConfigAuth implemented ConfigAuth for twitter provider
func (TwitterProvider) ConfigAuth(*auth.Auth) {
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

// Callback implement Callback with twitter provider
func (TwitterProvider) Callback(*http.Request, http.ResponseWriter, *auth.Claims) {
}

// ServeHTTP implement ServeHTTP with twitter provider
func (TwitterProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Claims) {
}
