package auth

import (
	"net/http"

	"github.com/qor/roles"
)

func (*Auth) Restrict(h http.Handler, permission *roles.Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get current user

		// get current user roles

		// check permission
		h.ServeHTTP(w, r)
	})
}
