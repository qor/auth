package authority

import (
	"github.com/ctdk/goiardi/role"
	"github.com/qor/auth"
)

// Authority authority struct
type Authority struct {
	Config *Config
}

// Config authority config
type Config struct {
	Auth *auth.Auth
	Role *role.Role
}

// New initialize Authority
func New(config *Config) *Authority {
	if config == nil {
		config = &Config{}
	}

	return Authority{Config: config}
}
