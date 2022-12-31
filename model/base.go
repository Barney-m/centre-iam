package model

import "time"

type BaseInfo struct {
	Modified  uint      `json:"modified"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedBy string    `json:"updatedBy"`
	UpdatedAt time.Time `json:"updatedAt"`
}
