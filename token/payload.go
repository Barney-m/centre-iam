package token

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// Hold payload data of the token
type Payload struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Issuer    string    `json:"issuer"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

// NewPayload creates a new token payload with specific email and duration
func NewPayload(email string, duration time.Duration) (*Payload, error) {
	tokenId, err := uuid.NewRandom()

	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenId,
		Email:     email,
		Issuer:    "stx",
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}

	return payload, nil
}

// Valid check if the payload is valid or not
func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return jwt.ErrTokenExpired
	}

	return nil
}
