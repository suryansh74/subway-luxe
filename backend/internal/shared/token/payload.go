package token

import (
	"errors"
	"time"

	"github.com/suryansh74/zomato/services/shared/models"
)

var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrExpiredToken = errors.New("token is expired")
)

type Payload struct {
	User      *models.TokenUser `json:"user"` // ✅ now has role
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiredAt time.Time         `json:"expired_at"`
}

func NewPayload(user *models.TokenUser, duration time.Duration) (*Payload, error) {
	return &Payload{
		User:      user,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}, nil
}

func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}
