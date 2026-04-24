package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	Admin          Role = "admin"
	Customer       Role = "customer"
	Seller         Role = "seller"
	DeliveryPerson Role = "delivery_person"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrInvalidOTP        = errors.New("invalid OTP")
	ErrOTPExpired        = errors.New("OTP has expired")
	ErrNameTooShort      = errors.New("name must be at least 3 characters")
	ErrPasswordMismatch  = errors.New("passwords do not match")
	ErrWeakPassword      = errors.New("password must contain at least one uppercase letter, one number, and one special character")
	ErrInternalServer    = errors.New("internal server error")
)

type User struct {
	ID                uuid.UUID  `json:"id"`
	Name              string     `json:"name"`
	Email             string     `json:"email"`
	Password          string     `json:"-"`
	Phone             *string    `json:"phone,omitempty"`
	PhoneCountryCode  *string    `json:"phone_country_code,omitempty"`
	ImagePath         *string    `json:"image_path,omitempty"`
	Role              Role       `json:"role"`
	Address           *string    `json:"address,omitempty"`
	IsEmailVerified   bool       `json:"is_email_verified"`
	IsPhoneVerified   bool       `json:"is_phone_verified"`
	EmailOtp          *string    `json:"-"`
	EmailOtpExpiresAt *time.Time `json:"-"`
	EmailOtpAttempts  int        `json:"-"`
	PhoneOtp          *string    `json:"-"`
	PhoneOtpExpiresAt *time.Time `json:"-"`
	PhoneOtpAttempts  int        `json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type RegisterInput struct {
	Name            string `json:"name" validate:"min=3,max=50"`
	Email           string `json:"email" validate:"email"`
	Password        string `json:"password"`
	PasswordConfirm string `json:"password_confirm"`
}

type LoginInput struct {
	Email    string `json:"email" validate:"email"`
	Password string `json:"password"`
}

type VerifyEmailInput struct {
	Otp string `json:"otp" validate:"len=6"`
}

type SendEmailOtpInput struct {
	Email string `json:"email" validate:"email"`
}

type VerifyPhoneInput struct {
	Phone string `json:"phone" validate:"required"`
	Otp   string `json:"otp" validate:"len=6"`
}

type SendPhoneOtpInput struct {
	Phone            string `json:"phone" validate:"required"`
	PhoneCountryCode string `json:"phone_country_code" validate:"required"`
}

type AuthResponse struct {
	User  *User  `json:"user"`
	Token string `json:"token,omitempty"`
}

type ErrorResponse struct {
	Error    string `json:"error"`
	Code     string `json:"code,omitempty"`
	Attempts int    `json:"attempts_remaining,omitempty"`
}
