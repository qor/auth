package auth

import "errors"

var (
	// ErrInvalidPassword invalid password error
	ErrInvalidPassword = errors.New("invalid password")
	// ErrInvalidAccount invalid account error
	ErrInvalidAccount = errors.New("invalid account")
	// ErrUnauthorized unauthorized error
	ErrUnauthorized = errors.New("Unauthorized")
	// ErrUnconfirmed unauthorized error
	ErrUnconfirmed = errors.New("You have to confirm your account before continuing")
)
