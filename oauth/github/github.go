package github

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/go-github/github"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/qor/utils"
	"golang.org/x/oauth2"
)

var (
	AuthorizeURL = "https://github.com/login/oauth/authorize"
	TokenURL     = "https://github.com/login/oauth/access_token"
)

// GithubProvider provide login with github method
type GithubProvider struct {
	*Config
}

// Config github Config
type Config struct {
	ClientID         string
	ClientSecret     string
	AuthorizeURL     string
	TokenURL         string
	RedirectURL      string
	Scopes           []string
	AuthorizeHandler func(*auth.Context) (interface{}, error)
}

func New(config *Config) *GithubProvider {
	if config == nil {
		config = &Config{}
	}

	provider := &GithubProvider{Config: config}

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

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (interface{}, error) {
			var (
				currentUser  interface{}
				schema       auth.Schema
				authInfo     auth_identity.Basic
				authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
				req          = context.Request
				tx           = context.Auth.GetDB(req)
			)

			state := req.URL.Query().Get("state")
			token, err := jwt.Parse(state, func(token *jwt.Token) (interface{}, error) {
				if token.Method != context.Auth.Config.SigningMethod {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return []byte(context.Auth.Config.SignedString), nil
			})

			if claims, ok := token.Claims.(*jwt.StandardClaims); ok && (!token.Valid || claims.Subject != "state") {
				return nil, auth.ErrUnauthorized
			}

			if err == nil {
				oauthCfg := provider.OAuthConfig(context)
				tkn, err := oauthCfg.Exchange(oauth2.NoContext, req.URL.Query().Get("code"))

				if err != nil {
					return nil, err
				}

				client := github.NewClient(oauthCfg.Client(oauth2.NoContext, tkn))
				user, _, err := client.Users.Get(oauth2.NoContext, "")
				if err != nil {
					return nil, err
				}

				{
					schema.Provider = provider.GetName()
					schema.UID = fmt.Sprint(*user.ID)
					schema.Info.Name = user.GetName()
					schema.Info.Email = user.GetEmail()
					schema.Info.Image = user.GetAvatarURL()
					schema.RawInfo = user
				}

				authInfo.Provider = provider.GetName()
				authInfo.UID = fmt.Sprint(*user.ID)

				if !tx.Model(authIdentity).Where(authInfo).Scan(&authInfo).RecordNotFound() {
					if authInfo.UserID != "" {
						return context.Auth.UserStorer.Get(authInfo.UserID, context)
					}

					return authInfo, nil
				}

				if context.Auth.Config.UserModel != nil {
					if _, userID, err := context.Auth.UserStorer.Save(&schema, context); err == nil {
						authInfo.UserID = userID
					} else {
						return nil, err
					}
				} else {
					currentUser = authIdentity
				}

				err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error
				return currentUser, err
			}

			return nil, err
		}
	}
	return provider
}

// GetName return provider name
func (GithubProvider) GetName() string {
	return "github"
}

// OAuthConfig return oauth config based on configuration
func (provider GithubProvider) OAuthConfig(context *auth.Context) *oauth2.Config {
	var (
		config = provider.Config
		req    = context.Request
		scheme = req.URL.Scheme
	)

	if scheme == "" {
		scheme = "http://"
	}

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizeURL,
			TokenURL: config.TokenURL,
		},
		RedirectURL: scheme + req.Host + context.Auth.AuthURL("github/callback"),
		Scopes:      config.Scopes,
	}
}

// Login implemented login with github provider
func (provider GithubProvider) Login(context *auth.Context) {
	token := jwt.NewWithClaims(context.Auth.Config.SigningMethod, jwt.StandardClaims{Subject: "state"})
	signedToken, _ := token.SignedString([]byte(context.Auth.Config.SignedString))

	url := provider.OAuthConfig(context).AuthCodeURL(signedToken)
	http.Redirect(context.Writer, context.Request, url, http.StatusFound)
}

// Logout implemented logout with github provider
func (GithubProvider) Logout(context *auth.Context) {
}

// Register implemented register with github provider
func (provider GithubProvider) Register(context *auth.Context) {
	provider.Login(context)
}

// Callback implement Callback with github provider
func (provider GithubProvider) Callback(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// ServeHTTP implement ServeHTTP with github provider
func (GithubProvider) ServeHTTP(*auth.Context) {
}
