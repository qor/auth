package authority

import (
	"net/http"
	"time"
)

// Rule authority rule definition
type Rule struct {
	TimeoutSinceLastAuth   time.Duration
	TimeoutSinceLastActive time.Duration
}

// ToHandler generate roles handler
func (Rule) ToHandler() Checker {
	return func(request *http.Request, user interface{}) bool {
	}
}
