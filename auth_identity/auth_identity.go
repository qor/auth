package auth_identity

import (
	"time"

	"github.com/jinzhu/gorm"
)

// AuthIdentity auth identity session model
type AuthIdentity struct {
	gorm.Model
	Basic
	SignLogs
}

// Basic basic information about auth identity
type Basic struct {
	Provider          string // phone, email, wechat, github...
	UID               string
	EncryptedPassword string
	UserID            string
	ConfirmedAt       *time.Time
}
