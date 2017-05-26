package database

import "github.com/jinzhu/gorm"

type AuthIdentity struct {
	gorm.Model
	Provider          string // phone, email, wechat, github...
	UID               string
	EncryptedPassword string
	AuthInfo          AuthInfo
	UserID            string

	Password             string `gorm:"-"`
	PasswordConfirmation string `gorm:"-"`
}
