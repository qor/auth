package twitter

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

// twitterProvider provide login with twitter method
type TwitterProvider struct {
	*Config
	OAuthConfig *oauth2.Config
}

// Config twitter Config
type Config struct {
	ClientID     string
	ClientSecret string
	AuthorizeURL string
	TokenURL     string
	RedirectURL  string
	Scopes       []string
}

func New(config *Config) *TwitterProvider {
	if config == nil {
		config = &Config{}
	}

	if config.ClientID == "" {
		panic(errors.New("Twitter's ClientID can't be blank"))
	}

	if config.ClientSecret == "" {
		panic(errors.New("Twitter's ClientSecret can't be blank"))
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

	return &TwitterProvider{Config: config, OAuthConfig: oauthCfg}
}

// GetName return provider name
func (TwitterProvider) GetName() string {
	return "twitter"
}

// ConfigAuth implemented ConfigAuth for twitter provider
func (TwitterProvider) ConfigAuth(*auth.Auth) {
}

// Login implemented login with twitter provider
func (provider TwitterProvider) Login(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
	token := jwt.New(session.Auth.Config.SigningMethod)
	token.Raw = "state"
	signedToken, _ := token.SignedString([]byte(session.Auth.Config.SignedString))

	url := provider.OAuthConfig.AuthCodeURL(signedToken)
	http.Redirect(writer, request, url, http.StatusFound)
}

// Logout implemented logout with twitter provider
func (TwitterProvider) Logout(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Register implemented register with twitter provider
func (TwitterProvider) Register(request *http.Request, writer http.ResponseWriter, session *auth.Session) {
}

// Callback implement Callback with twitter provider
func (TwitterProvider) Callback(*http.Request, http.ResponseWriter, *auth.Session) {
}

// ServeHTTP implement ServeHTTP with twitter provider
func (TwitterProvider) ServeHTTP(*http.Request, http.ResponseWriter, *auth.Session) {
}
