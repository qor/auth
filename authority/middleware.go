package authority

import (
	"net/http"
	"time"
)

// Middleware authority middleware used to record activity time
func (authority *Authority) Middleware(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if claims, err := authority.Auth.Get(req); err == nil {
			lastActivityTime := claims.LastActivityTime
			if lastActivityTime != nil {
				lastDistractionTime := time.Now().Sub(*lastActivityTime)

				if claims.LongestDistractionTimeSinceLastLogin == nil || *claims.LongestDistractionTimeSinceLastLogin < lastDistractionTime {
					claims.LongestDistractionTimeSinceLastLogin = &lastDistractionTime
				}
			}
		}
	})
}
