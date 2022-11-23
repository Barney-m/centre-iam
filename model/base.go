package model

import "time"

type BaseInfo struct {
	MdfCnt uint      `json:"mdfCnt"`
	CrtBy  string    `json:"crtBy"`
	CrtAt  time.Time `json:"crtAt"`
	UpdBy  string    `json:"updBy"`
	UpdAt  time.Time `json:"updAt"`
}
