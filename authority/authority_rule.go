package authority

import (
	"net/http"
	"time"

	"github.com/qor/roles"
)

// Rule authority rule's definition
type Rule struct {
	TimeoutSinceLastAuth   time.Duration
	TimeoutSinceLastActive time.Duration
	LoggedAs               []string
}

// ToHandler generate roles checker
func (authority Authority) ToHandler(rule Rule) roles.Checker {
	return func(req *http.Request, user interface{}) bool {
		claims, err := authority.Auth.GetClaims(req)

		if err != nil {
			return false
		}

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
