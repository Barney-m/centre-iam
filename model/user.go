package model

import (
	"time"

	"github.com/google/uuid"
)

type CtrUsr struct {
	UsrId    uuid.UUID `gorm:"primaryKey" json:"-"`
	Email    string    `json:"email"`
	FullNm   string    `json:"full_name"`
	Addr     string    `json:"address"`
	Dob      time.Time `json:"dob"`
	MblNo    string    `json:"mobile_no"`
	UsrSts   string    `json:"user_status"`
	IsFrtIdc bool      `json:"is_frt_idc"`
}
