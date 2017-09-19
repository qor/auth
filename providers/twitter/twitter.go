package twitter

import (
	"github.com/qor/auth"
	"github.com/qor/auth/claims"
)

// Provider provide login with twitter
type Provider struct {
	*Config
}

// Config twitter Config
type Config struct {
	ClientID         string
	ClientSecret     string
	AuthorizeURL     string
	TokenURL         string
	RedirectURL      string
	AuthorizeHandler func(context *auth.Context) (*claims.Claims, error)
}

func New(config *Config) *Provider {
	if config == nil {
		config = &Config{}
	}

	provider := &Provider{Config: config}

	return provider
}

// Login implemented login with twitter provider
func (provider Provider) Login(context *auth.Context) {
	claims := claims.Claims{}
	claims.Subject = "state"
	signedToken := context.Auth.SessionStorer.SignedToken(&claims)

	// TODO
}

// Logout implemented logout with twitter provider
func (Provider) Logout(context *auth.Context) {
}

// Register implemented register with twitter provider
func (provider Provider) Register(context *auth.Context) {
	provider.Login(context)
}

// Callback implement Callback with twitter provider
func (provider Provider) Callback(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// ServeHTTP implement ServeHTTP with twitter provider
func (Provider) ServeHTTP(*auth.Context) {
}
