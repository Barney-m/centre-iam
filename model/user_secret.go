package model

import "github.com/google/uuid"

type CentreUserSecret struct {
	UserId       uuid.UUID `gorm:"column:USER_ID"`
	Username     string    `gorm:"column:USERNAME"`
	Password     string    `gorm:"column:PASSWORD"`
	Salt         []byte    `gorm:"column:SALT"`
	RefreshToken string    `gorm:"column:REFRESH_TOKEN"`
	EncryptAlgo  string    `gorm:"column:ENCRYPT_ALGO"`
	HashAlgo     string    `gorm:"column:HASH_ALGO"`
}
