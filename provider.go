package auth

// Provider define Provider interface
type Provider interface {
	GetName() string

	Login(*Context)
	Logout(*Context)
	Register(*Context)
	Callback(*Context)
	ServeHTTP(*Context)
}
