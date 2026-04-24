package domain

import "context"

type UserRepository interface {
	Create(ctx context.Context, arg CreateUserParams) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	GetByPhone(ctx context.Context, phone string) (*User, error)
	Update(ctx context.Context, arg UpdateUserParams) (*User, error)
	SetEmailOTP(ctx context.Context, userID string, otp string, expiresAt string, attempts int) (*User, error)
	SetPhoneOTP(ctx context.Context, userID string, otp string, expiresAt string, attempts int) (*User, error)
	ClearEmailOTP(ctx context.Context, userID string) (*User, error)
	ClearPhoneOTP(ctx context.Context, userID string) (*User, error)
	UpdateRole(ctx context.Context, userID string, role string) (*User, error)
}

type EmailSender interface {
	SendEmailOTP(ctx context.Context, to string, otp string) error
}

type PhoneSender interface {
	SendPhoneOTP(ctx context.Context, to string, otp string) error
}

type CreateUserParams struct {
	Name     string
	Email    string
	Password string
	Role     string
}

type UpdateUserParams struct {
	ID               string
	Name             string
	Email            string
	Phone            *string
	PhoneCountryCode *string
	ImagePath        *string
	Role             string
	Address          *string
	IsEmailVerified  bool
	IsPhoneVerified  bool
}
