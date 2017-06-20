package auth

import "time"

// Schema auth schema
type Schema struct {
	Provider string
	UID      string
	Info     struct {
		Name      string
		Email     string
		FirstName string
		LastName  string
		Location  string
		Image     string
		Phone     string
	}
	Credentials struct {
		Token     string
		Secret    string
		ExpiresAt *time.Time
	}
	RawInfo interface{}
}
