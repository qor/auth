package authority

import (
	"context"
	"net/http"
	"time"

	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// ClaimsContextKey authority claims key
var ClaimsContextKey utils.ContextKey = "authority_claims"

// Middleware authority middleware used to record activity time
func (authority *Authority) Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var reqClaims claims.Claims
		if claims, err := authority.Auth.Get(req); err == nil {
			reqClaims = *claims

			lastActiveAt := claims.LastActiveAt
			if lastActiveAt != nil {
				lastDistractionTime := time.Now().Sub(*lastActiveAt)

				if claims.LongestDistractionSinceLastLogin == nil || *claims.LongestDistractionSinceLastLogin < lastDistractionTime {
					claims.LongestDistractionSinceLastLogin = &lastDistractionTime
				}
			}

			now := time.Now()
			claims.LastActiveAt = &now

			authority.Auth.Update(claims, req)
		}

		ctx := context.WithValue(req.Context(), ClaimsContextKey, reqClaims)
		handler.ServeHTTP(w, req.WithContext(ctx))
	})
}
