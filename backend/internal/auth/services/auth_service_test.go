package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/suryansh74/subway-luxe/internal/auth/domain"
	"github.com/suryansh74/subway-luxe/internal/auth/infrastructure/adapters"
	"github.com/suryansh74/subway-luxe/internal/auth/repositories"
	"github.com/suryansh74/subway-luxe/internal/shared/models"
	"github.com/suryansh74/subway-luxe/pkg/logger"
)

func init() {
	logger.Init("development")
}

type mockTokenMaker struct {
	tokens map[string]string
}

func (m *mockTokenMaker) CreateToken(user *models.TokenUser, duration time.Duration) (string, error) {
	token := "mock-token-" + user.ID
	m.tokens[token] = user.ID
	return token, nil
}

func (m *mockTokenMaker) VerifyToken(token string) (*models.TokenUser, error) {
	if userID, ok := m.tokens[token]; ok {
		return &models.TokenUser{ID: userID}, nil
	}
	return nil, domain.ErrInvalidPassword
}

func TestRegister_Success(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	input := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}

	resp, err := service.Register(context.Background(), input)

	require.NoError(t, err)
	assert.NotNil(t, resp.User)
	assert.Equal(t, "John Doe", resp.User.Name)
	assert.Equal(t, "john@example.com", resp.User.Email)
	assert.False(t, resp.User.IsEmailVerified)
	assert.NotEmpty(t, resp.Token)

	// Verify OTP was sent
	assert.Contains(t, emailSender.SentOTPs, "john@example.com")
}

func TestRegister_NameTooShort(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	input := domain.RegisterInput{
		Name:            "Jo",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}

	_, err := service.Register(context.Background(), input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrNameTooShort, err)
}

func TestRegister_PasswordMismatch(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	input := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password2!",
	}

	_, err := service.Register(context.Background(), input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrPasswordMismatch, err)
}

func TestRegister_WeakPassword(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	tests := []struct {
		name  string
		email string
	}{
		{"password", "test@example.com"},
		{"PASSWORD1!", "test@example.com"},
		{"Password1", "test@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := domain.RegisterInput{
				Name:            "John Doe",
				Email:           tt.email,
				Password:        tt.name,
				PasswordConfirm: tt.name,
			}

			_, err := service.Register(context.Background(), input)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "password must contain")
		})
	}
}

func TestRegister_UserAlreadyExists(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	input := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}

	_, err := service.Register(context.Background(), input)
	require.NoError(t, err)

	// Try to register again
	_, err = service.Register(context.Background(), input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserAlreadyExists, err)
}

func TestLogin_Success(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	// First register a user
	registerInput := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}
	_, err := service.Register(context.Background(), registerInput)
	require.NoError(t, err)

	// Now try to login
	loginInput := domain.LoginInput{
		Email:    "john@example.com",
		Password: "Password1!",
	}

	resp, err := service.Login(context.Background(), loginInput)

	require.NoError(t, err)
	assert.NotNil(t, resp.User)
	assert.Equal(t, "john@example.com", resp.User.Email)
	assert.NotEmpty(t, resp.Token)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	input := domain.LoginInput{
		Email:    "nonexistent@example.com",
		Password: "Password1!",
	}

	_, err := service.Login(context.Background(), input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidPassword, err)
}

func TestVerifyEmail_Success(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	// Register user
	registerInput := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}
	resp, err := service.Register(context.Background(), registerInput)
	require.NoError(t, err)

	// Get the OTP that was sent
	otp := emailSender.SentOTPs["john@example.com"]
	require.NotEmpty(t, otp)

	// Verify email
	updatedUser, err := service.VerifyEmail(context.Background(), resp.User.ID.String(), otp)

	require.NoError(t, err)
	assert.True(t, updatedUser.IsEmailVerified)
}

func TestVerifyEmail_InvalidOTP(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	// Register user
	registerInput := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}
	resp, err := service.Register(context.Background(), registerInput)
	require.NoError(t, err)

	// Try to verify with wrong OTP
	_, err = service.VerifyEmail(context.Background(), resp.User.ID.String(), "000000")

	assert.Error(t, err)
}

func TestVerifyPhone_Success(t *testing.T) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockTokenMaker{tokens: make(map[string]string)}

	service := NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	// Register and verify email first
	registerInput := domain.RegisterInput{
		Name:            "John Doe",
		Email:           "john@example.com",
		Password:        "Password1!",
		PasswordConfirm: "Password1!",
	}
	resp, err := service.Register(context.Background(), registerInput)
	require.NoError(t, err)

	// Verify email first
	emailOTP := emailSender.SentOTPs["john@example.com"]
	_, err = service.VerifyEmail(context.Background(), resp.User.ID.String(), emailOTP)
	require.NoError(t, err)

	// Send phone OTP - countryCode should include + already
	err = service.SendPhoneOTP(context.Background(), resp.User.ID.String(), "1234567890", "+1")
	require.NoError(t, err)

	// Get the OTP - key is fullPhone = countryCode + phone
	phoneOTP := phoneSender.SentOTPs["+11234567890"]
	require.NotEmpty(t, phoneOTP)

	// Verify phone
	updatedUser, err := service.VerifyPhone(context.Background(), resp.User.ID.String(), phoneOTP)

	require.NoError(t, err)
	assert.True(t, updatedUser.IsPhoneVerified)
}
