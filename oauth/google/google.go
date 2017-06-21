package google

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/qor/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var UserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"

// GoogleProvider provide login with google method
type GoogleProvider struct {
	*Config
}

// Config google Config
type Config struct {
	ClientID         string
	ClientSecret     string
	AuthorizeURL     string
	TokenURL         string
	RedirectURL      string
	Scopes           []string
	AuthorizeHandler func(context *auth.Context) (interface{}, error)
}

func New(config *Config) *GoogleProvider {
	if config == nil {
		config = &Config{}
	}

	provider := &GoogleProvider{Config: config}

	if config.ClientID == "" {
		panic(errors.New("Google's ClientID can't be blank"))
	}

	if config.ClientSecret == "" {
		panic(errors.New("Google's ClientSecret can't be blank"))
	}

	if config.AuthorizeURL == "" {
		config.AuthorizeURL = google.Endpoint.AuthURL
	}

	if config.TokenURL == "" {
		config.TokenURL = google.Endpoint.TokenURL
	}

	if len(config.Scopes) == 0 {
		config.Scopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
	}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = func(context *auth.Context) (interface{}, error) {
			var (
				req          = context.Request
				currentUser  interface{}
				authInfo     auth_identity.Basic
				tx           = context.Auth.GetDB(req)
				authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
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

				client := oauthCfg.Client(oauth2.NoContext, tkn)
				resp, err := client.Get(UserInfoURL)
				if err != nil {
					return nil, err
				}

				defer resp.Body.Close()
				email, _ := ioutil.ReadAll(resp.Body)

				authInfo.Provider = provider.GetName()
				authInfo.UID = string(email)

				if !tx.Model(authIdentity).Where(authInfo).Scan(&authInfo).RecordNotFound() {
					if context.Auth.Config.UserModel != nil {
						if authInfo.UserID == "" {
							return nil, auth.ErrInvalidAccount
						}
						currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
						err := tx.First(currentUser, authInfo.UserID).Error
						return currentUser, err
					}
					return authInfo, nil
				}

				if context.Auth.Config.UserModel != nil {
					currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
					if err = tx.Create(currentUser).Error; err == nil {
						authInfo.UserID = fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue())
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
func (GoogleProvider) GetName() string {
	return "google"
}

// OAuthConfig return oauth config based on configuration
func (provider GoogleProvider) OAuthConfig(context *auth.Context) *oauth2.Config {
	var (
		config = provider.Config
		scheme = context.Request.URL.Scheme
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
		RedirectURL: scheme + context.Request.Host + context.Auth.AuthURL("google/callback"),
		Scopes:      config.Scopes,
	}
}

// Login implemented login with google provider
func (provider GoogleProvider) Login(context *auth.Context) {
	token := jwt.NewWithClaims(context.Auth.Config.SigningMethod, jwt.StandardClaims{Subject: "state"})
	signedToken, _ := token.SignedString([]byte(context.Auth.Config.SignedString))

	url := provider.OAuthConfig(context).AuthCodeURL(signedToken)
	http.Redirect(context.Writer, context.Request, url, http.StatusFound)
}

// Logout implemented logout with google provider
func (GoogleProvider) Logout(context *auth.Context) {
}

// Register implemented register with google provider
func (provider GoogleProvider) Register(context *auth.Context) {
	provider.Login(context)
}

// Callback implement Callback with google provider
func (provider GoogleProvider) Callback(context *auth.Context) {
	context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// ServeHTTP implement ServeHTTP with google provider
func (GoogleProvider) ServeHTTP(*auth.Context) {
}
