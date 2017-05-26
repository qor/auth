package database

import (
	"errors"
	"time"

	"github.com/jinzhu/gorm"
)

type SignLog struct {
	UserAgent string
	At        *time.Time
	IP        string
}

type AuthInfo struct {
	PhoneVerificationCode       string
	PhoneVerificationCodeExpiry *time.Time
	PhoneConfirmedAt            *time.Time
	UnconfirmedPhone            string // only use when changing phone number

	EmailConfirmedAt *time.Time
	UnconfirmedEmail string // only use when changing email

	SignInCount uint
	SignLogs    []SignLog
}

type User struct {
	gorm.Model

	Login    string // login name
	Email    string // email
	Phone    string // phone
	AuthInfo AuthInfo

	EncryptedPassword    string
	Password             string `gorm:"-"`
	PasswordConfirmation string `gorm:"-"`
}

func (user *User) VerifyPhone(code string) error {
	now := time.Now()
	if code == user.AuthInfo.PhoneVerificationCode && (user.AuthInfo.PhoneVerificationCodeExpiry == nil || user.AuthInfo.PhoneVerificationCodeExpiry.After(now)) {
		if user.AuthInfo.UnconfirmedPhone != "" {
			user.Phone = user.AuthInfo.UnconfirmedPhone
			user.AuthInfo.UnconfirmedPhone = ""
		}
		user.AuthInfo.PhoneConfirmedAt = &now

		return nil
	}

	return errors.New("failed to verify phone")
}

func (user *User) BeforeCreate(tx *gorm.DB) error {
	return nil
}

func (user *User) BeforeSave(tx *gorm.DB) error {
	return nil
}

// reset password
// confirmed at
// unconfirmed email
// roles
// phone, verification code
