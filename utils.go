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

	claims, err := auth.SessionStorer.Get(req)
	if err == nil {
		context := &Context{Auth: auth, Claims: claims, Request: req}
		if user, err := auth.UserStorer.Get(claims, context); err == nil {
			return user
		}
	}

	return nil
}

// Login sign user in
func (auth *Auth) Login(claimer claims.ClaimerInterface, req *http.Request) error {
	return auth.SessionStorer.Update(claimer.ToClaims(), req)
}
