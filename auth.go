package auth

import (
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/qor/admin"
)

type Auth struct {
	*Config
	providers map[string]Provider
	viewpaths []string
}

type Config struct {
	SigningMethod   jwt.SigningMethod
	SignedString    string
	AssetFileSystem admin.AssetFSInterface
}

// New initialize Auth
func New(config *Config) *Auth {
	if config == nil {
		config = &Config{}
	}

	if config.SigningMethod == nil {
		config.SigningMethod = jwt.SigningMethodHS256
	}

	if config.AssetFileSystem == nil {
		config.AssetFileSystem = &admin.AssetFileSystem{}
	}

	auth := &Auth{Config: config, providers: map[string]Provider{}}
	auth.RegisterViewPath("app/views")

	return auth
}

// RegisterViewPath register view path
func (auth *Auth) RegisterViewPath(pth string) {
	auth.viewpaths = append(auth.viewpaths, pth)
	auth.Config.AssetFileSystem.RegisterPath(pth)
}

// SetAssetFS set asset fs for render
func (auth *Auth) SetAssetFS(assetFS admin.AssetFSInterface) {
	for _, viewPath := range auth.viewPaths {
		assetFS.RegisterPath(viewPath)
	}

	auth.AssetFileSystem = assetFS
}

// RegisterProvider register auth provider
func (auth *Auth) RegisterProvider(provider Provider) {
	name := provider.GetProviderName()
	if _, ok := auth.providers[name]; ok {
		fmt.Printf("warning: auth provider %v already registered", name)
	}

	auth.providers[name] = provider
}

// GetProvider get provider with name
func (auth *Auth) GetProvider(name string) Provider {
	return auth.providers[name]
}

// SignedToken generate signed token with Claims
func (auth *Auth) SignedToken(claims *Claims) string {
	// TODO
	// update based on configuration claims.ExpiresAt

	token := jwt.NewWithClaims(auth.SigningMethod, claims)
	signedToken, _ := token.SignedString([]byte(auth.SignedString))

	return signedToken
}

// Validate validate auth token
func (auth *Auth) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != auth.Config.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(auth.Config.SignedString), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
