package model

import (
	"time"

	"github.com/google/uuid"
)

type CentreUser struct {
	UserId         uuid.UUID `gorm:"primaryKey;column:USER_ID" json:"-"`
	Email          string    `gorm:"column:EMAIL" json:"email"`
	FullName       string    `gorm:"column:FULL_NAME" json:"fullName"`
	Address        string    `gorm:"column:ADDRESS" json:"address"`
	Dob            time.Time `gorm:"column:DOB" json:"dob"`
	MobileNo       string    `gorm:"column:MOBILE_NO" json:"mobileNo"`
	Rank           string    `gorm:"column:RANK" json:"rank"`
	UserStatus     string    `gorm:"column:USER_STATUS" json:"userStatus"`
	IsFirstTimeIdc bool      `gorm:"column:IS_FIRST_TIME_IDC" json:"isFirstTimeIdc"`
}
