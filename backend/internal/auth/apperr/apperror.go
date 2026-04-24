package apperr

import "errors"

var (
	ErrInternalServer    = errors.New("internal server error")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrInvalidOTP        = errors.New("invalid OTP")
	ErrOTPExpired        = errors.New("OTP has expired")
	ErrOTPMaxAttempts    = errors.New("maximum OTP attempts exceeded")
	ErrInvalidEmail      = errors.New("invalid email format")
	ErrWeakPassword      = errors.New("password must contain at least one uppercase letter, one number, and one special character")
	ErrPasswordMismatch  = errors.New("passwords do not match")
	ErrNameTooShort      = errors.New("name must be at least 3 characters")
	ErrEmailNotVerified  = errors.New("email not verified")
	ErrPhoneNotVerified  = errors.New("phone not verified")
)
