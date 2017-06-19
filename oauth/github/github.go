package github

import (
	"errors"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/auth"
	"golang.org/x/oauth2"
)

var (
	AuthorizeURL = "https://github.com/login/oauth/authorize"
	TokenURL     = "https://github.com/login/oauth/access_token"
)

// githubProvider provide login with github method
type GithubProvider struct {
	*Config
	OAuthConfig *oauth2.Config
}

// Config github Config
type Config struct {
	ClientID     string
	ClientSecret string
	AuthorizeURL string
	TokenURL     string
	RedirectURL  string
	Scopes       []string
}

func New(config *Config) *GithubProvider {
	if config == nil {
		config = &Config{}
	}

	if config.ClientID == "" {
		panic(errors.New("Github's ClientID can't be blank"))
	}

	if config.ClientSecret == "" {
		panic(errors.New("Github's ClientSecret can't be blank"))
	}

	if config.AuthorizeURL == "" {
		config.AuthorizeURL = AuthorizeURL
	}

	if config.TokenURL == "" {
		config.TokenURL = TokenURL
	}

	oauthCfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizeURL,
			TokenURL: config.TokenURL,
		},
		RedirectURL: config.RedirectURL,
		Scopes:      config.Scopes,
	}

	return &GithubProvider{Config: config, OAuthConfig: oauthCfg}
}

// GetName return provider name
func (GithubProvider) GetName() string {
	return "github"
}

// ConfigAuth implemented ConfigAuth for github provider
func (GithubProvider) ConfigAuth(*auth.Auth) {
}

// Login implemented login with github provider
func (provider GithubProvider) Login(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	token := jwt.New(session.Auth.Config.SigningMethod)
	token.Raw = "state"
	signedToken, _ := token.SignedString([]byte(session.Auth.Config.SignedString))

	url := provider.OAuthConfig.AuthCodeURL(signedToken)
	http.Redirect(writer, request, url, http.StatusFound)
}

// Logout implemented logout with github provider
func (GithubProvider) Logout(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Register implemented register with github provider
func (GithubProvider) Register(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Callback implement Callback with github provider
func (GithubProvider) Callback(*http.Request, http.ResponseWriter, *auth.Session) {
}

// ServeHTTP implement ServeHTTP with github provider
func (GithubProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Session) {
}
