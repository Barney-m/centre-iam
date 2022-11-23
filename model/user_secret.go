package model

import "github.com/google/uuid"

type CtrUsrSct struct {
	UsrId    uuid.UUID
	Usrnm    string
	Pwd      string
	Salt     []byte
	RfhTkn   string
	EnctAlgo string
	HashAlgo string
}
