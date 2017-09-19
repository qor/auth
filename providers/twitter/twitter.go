package twitter

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/mrjones/oauth"
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

	provider := &Provider{Config: config}

	if config.ClientID == "" {
		panic(errors.New("Twitter's ClientID can't be blank"))
	}

	if config.ClientSecret == "" {
		panic(errors.New("Twitter's ClientSecret can't be blank"))
	}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
			consumer := provider.NewConsumer(context)
			requestToken := ""
			fmt.Println(consumer)
			fmt.Println(requestToken)
			fmt.Println(context.Request.URL.String())

			return nil, nil
		}
	}

	return provider
}

// GetName return provider name
func (Provider) GetName() string {
	return "twitter"
}

// ConfigAuth config auth
func (provider Provider) ConfigAuth(auth *auth.Auth) {
	auth.Render.RegisterViewPath("github.com/qor/auth/providers/twitter/views")
}

// NewConsumer new twitter consumer
func (provider Provider) NewConsumer(context *auth.Context) *oauth.Consumer {
	scheme := context.Request.URL.Scheme

	if scheme == "" {
		scheme = "http://"
	}

	return oauth.NewConsumer(provider.ClientID, provider.ClientSecret, oauth.ServiceProvider{
		RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
		AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
		AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
	})
}

// Login implemented login with twitter provider
func (provider Provider) Login(context *auth.Context) {
	consumer := provider.NewConsumer(context)
	requestToken, u, err := consumer.GetRequestTokenAndUrl("oob")

	if err == nil {
		// save requestToken into session
		fmt.Println(requestToken)
		http.Redirect(context.Writer, context.Request, u, http.StatusFound)
		return
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
