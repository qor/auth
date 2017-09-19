package twitter

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/dghubble/oauth1"
	"github.com/dghubble/oauth1/twitter"
	"github.com/qor/auth"
	"github.com/qor/auth/claims"
	"github.com/qor/session"
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

	if config.ClientID == "" {
		panic(errors.New("Twitter's ClientID can't be blank"))
	}

	if config.ClientSecret == "" {
		panic(errors.New("Twitter's ClientSecret can't be blank"))
	}

	provider := &Provider{Config: config}

	return provider
}

// Login implemented login with twitter provider
func (provider Provider) Login(context *auth.Context) {
	var scheme = context.Request.URL.Scheme

	if scheme == "" {
		scheme = "http://"
	}

	config := oauth1.Config{
		ConsumerKey:    provider.ClientID,
		ConsumerSecret: provider.ClientSecret,
		CallbackURL:    scheme + context.Request.Host + context.Auth.AuthURL("twitter/callback"),
		Endpoint:       twitter.AuthorizeEndpoint,
	}

	requestToken, _, err := config.RequestToken()

	if err == nil {
		var authorizationURL *url.URL
		authorizationURL, err = config.AuthorizationURL(requestToken)
		if err == nil {
			http.Redirect(context.Writer, context.Request, authorizationURL.String(), http.StatusFound)
			return
		}
	}

	context.SessionStorer.Flash(context.Writer, context.Request, session.Message{Message: template.HTML(err.Error()), Type: "error"})
	context.Auth.Config.Render.Execute("auth/login", context, context.Request, context.Writer)
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
