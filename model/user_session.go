package model

import (
	"time"

	"github.com/google/uuid"
)

type CentreUserSession struct {
	SessionId    uuid.UUID `gorm:"column:SESSION_ID"`
	Username     string    `gorm:"column:USERNAME"`
	Email        string    `gorm:"column:EMAIL"`
	RefreshToken string    `gorm:"column:REFRESH_TOKEN"`
	UserAgent    string    `gorm:"column:USER_AGENT"`
	ClientIp     string    `gorm:"column:CLIENT_IP"`
	IsBlock      bool      `gorm:"column:IS_BLOCK"`
	ExpireAt     time.Time `gorm:"column:EXPIRE_AT"`
}
