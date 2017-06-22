package auth

import (
	"context"
	"net/http"

	"github.com/qor/roles"
)

type contextKey string

// CurrentUser context key to get current user from Request
const CurrentUser contextKey = "CurrentUser"

// GetCurrentUser get current user from request
func (auth *Auth) GetCurrentUser(w http.ResponseWriter, req *http.Request) interface{} {
	if currentUser := req.Context().Value(CurrentUser); currentUser != nil {
		return currentUser
	}

	tokenString := req.Header.Get("Authorization")

	// Get Token from Cookie
	if tokenString == "" {
		if cookie, err := req.Cookie(auth.Config.SessionName); err == nil {
			tokenString = cookie.Value
		}
	}

	claims, err := auth.Validate(tokenString)
	if err == nil {
		context := &Context{Auth: auth, Claims: claims, Request: req, Writer: w}
		if user, err := auth.UserStorer.Get(claims, context); err == nil {
			return user
		}
	}

	return nil
}

// Restrict restrict middleware
func (auth *Auth) Restrict(h http.Handler, permission *roles.Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get Token from Header
		var (
			hasPermission bool
			matchedRoles  []string
			currentUser   = auth.GetCurrentUser(w, req)
		)

		// get current user
		if currentUser != nil {
			req.WithContext(context.WithValue(req.Context(), CurrentUser, currentUser))
		}

		// get current user roles
		matchedRoles = permission.Role.MatchedRoles(req, currentUser)

		switch req.Method {
		case "GET":
			hasPermission = permission.HasPermission(roles.Read, matchedRoles...)
		case "PUT":
			hasPermission = permission.HasPermission(roles.Update, matchedRoles...)
		case "POST":
			hasPermission = permission.HasPermission(roles.Create, matchedRoles...)
		case "DELETE":
			hasPermission = permission.HasPermission(roles.Delete, matchedRoles...)
		}

		if hasPermission {
			h.ServeHTTP(w, req)
		} else {
			http.Redirect(w, req, auth.AuthURL("login"), http.StatusSeeOther)
		}
	})
}
