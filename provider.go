package auth

// Provider define Provider interface
type Provider interface {
	GetName() string

	ConfigAuth(*Auth)
	Login(*Context)
	Logout(*Context)
	Register(*Context)
	Callback(*Context)
	ServeHTTP(*Context)
}
