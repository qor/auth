package auth

import (
	"context"
	"net/http"

	"github.com/qor/roles"
)

const CurrentUser string = "CurrentUser"

func (*Auth) Restrict(h http.Handler, permission *roles.Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get current user
		var currentUser interface{}
		var hasPermission bool

		if currentUser != nil {
			r.WithContext(context.WithValue(r.Context(), CurrentUser, currentUser))
		}

		// get current user roles
		matchedRoles := permission.Role.MatchedRoles(r, currentUser)

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
