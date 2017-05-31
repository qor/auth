package auth

import (
	"context"
	"net/http"

	"github.com/qor/roles"
)

const CurrentUser string = "CurrentUser"

func (auth *Auth) Restrict(h http.Handler, permission *roles.Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get Token from Header
		var (
			currentUser   interface{}
			hasPermission bool
			matchedRoles  []string
			tokenString   = r.Header.Get("Authorization")
		)

		// Get Token from Cookie
		if tokenString == "" {
			if cookie, err := r.Cookie("_session"); err == nil {
				tokenString = cookie.Value
			}
		}

		claims, err := auth.Validate(tokenString)

		if err == nil {
			if provider := auth.GetProvider(claims.Type); provider != nil {
				currentUser = nil // provider.GetCurrentUser(r, w, claims)

				// get current user
				if currentUser != nil {
					r.WithContext(context.WithValue(r.Context(), CurrentUser, currentUser))
				}
			}
		}

		// get current user roles
		matchedRoles = permission.Role.MatchedRoles(r, currentUser)

		switch r.Method {
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
			h.ServeHTTP(w, r)
		} else {
			// redirect to login page
		}
	})
}
