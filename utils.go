package auth

import (
	"net/http"

	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "current_user"

// GetCurrentUser get current user from request
func (auth *Auth) GetCurrentUser(req *http.Request) interface{} {
	if currentUser := req.Context().Value(CurrentUser); currentUser != nil {
		return currentUser
	}

	tokenString := req.Header.Get("Authorization")

	// Get Token from Cookie
	if tokenString == "" {
		tokenString = auth.SessionManager.Get(req, auth.Config.SessionName)
	}

	claims, err := auth.Validate(tokenString)
	if err == nil {
		context := &Context{Auth: auth, Claims: claims, Request: req}
		if user, err := auth.UserStorer.Get(claims, context); err == nil {
			return user
		}
	}

	return nil
}

// Logout sign current user out
func (auth *Auth) Logout(w http.ResponseWriter, req *http.Request) {
	context := &Context{Auth: auth, Request: req, Writer: w}
	auth.LogoutHandler(context)
}

// Login sign user in
func (auth *Auth) Login(claimer claims.ClaimerInterface, req *http.Request) error {
	claims := claimer.ToClaims()
	token := auth.SignedToken(claims)
	return auth.SessionManager.Add(req, auth.Config.SessionName, token)
}
