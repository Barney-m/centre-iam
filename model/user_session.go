package model

import (
	"time"

	"github.com/google/uuid"
)

type CtrUsrSss struct {
	SssId  uuid.UUID
	Usrnm  string
	Email  string
	RfhTkn string
	UsrAgt string
	CltIp  string
	IsBlck bool
	ExpAt  time.Time
}
