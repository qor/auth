package authority

import (
	"net/http"
	"time"

	"github.com/qor/auth/claims"
	"github.com/qor/roles"
)

// Rule authority rule's definition
type Rule struct {
	TimeoutSinceLastAuth   time.Duration
	TimeoutSinceLastActive time.Duration
	LoggedAs               []string
}

// Handler generate roles checker
func (authority Authority) Handler(rule Rule) roles.Checker {
	return func(req *http.Request, user interface{}) bool {
		claims, _ := req.Context().Value(ClaimsContextKey).(claims.Claims)

		// Check Last Auth
		if rule.TimeoutSinceLastAuth > 0 {
			if claims.LastAuthTime == nil || time.Now().Add(-rule.TimeoutSinceLastAuth).After(*claims.LastAuthTime) {
				return false
			}
		}

		// Check Last Active
		if rule.TimeoutSinceLastActive > 0 {
			if claims.LastActivityTime == nil || time.Now().Add(-rule.TimeoutSinceLastActive).After(*claims.LastActivityTime) {
				return false
			}
		}

		// Check LoggedAs
		if len(rule.LoggedAs) > 0 {
			for _, as := range rule.LoggedAs {
				for _, cas := range claims.LoggedAs {
					if as == cas {
						return true
					}
				}
			}

			return false
		}

		return true
	}
}

// Register register authority rule into Role
func (authority *Authority) Register(name string, rule Rule) {
	authority.Config.Role.Register(name, authority.Handler(rule))
}

// Allow Check allow role or not
func (authority *Authority) Allow(role string, req *http.Request) bool {
	currentUser := authority.Auth.GetCurrentUser(req)
	return authority.Role.HasRole(req, currentUser, role)
}
