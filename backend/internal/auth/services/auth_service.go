package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/suryansh74/subway-luxe/internal/auth/apperr"
	"github.com/suryansh74/subway-luxe/internal/auth/domain"
	"github.com/suryansh74/subway-luxe/internal/shared/models"
	"github.com/suryansh74/subway-luxe/pkg/logger"
	"golang.org/x/crypto/argon2"
)

type TokenMaker interface {
	CreateToken(user *models.TokenUser, duration time.Duration) (string, error)
	VerifyToken(token string) (*models.TokenUser, error)
}

type AuthService struct {
	repo           domain.UserRepository
	emailSender    domain.EmailSender
	phoneSender    domain.PhoneSender
	tokenMaker     TokenMaker
	accessDuration time.Duration
	otpExpiryMins  int
	otpMaxAttempts int
}

func NewAuthService(
	repo domain.UserRepository,
	emailSender domain.EmailSender,
	phoneSender domain.PhoneSender,
	tokenMaker TokenMaker,
	accessDuration time.Duration,
	otpExpiryMins int,
	otpMaxAttempts int,
) *AuthService {
	return &AuthService{
		repo:           repo,
		emailSender:    emailSender,
		phoneSender:    phoneSender,
		tokenMaker:     tokenMaker,
		accessDuration: accessDuration,
		otpExpiryMins:  otpExpiryMins,
		otpMaxAttempts: otpMaxAttempts,
	}
}

func (s *AuthService) Register(ctx context.Context, input domain.RegisterInput) (*domain.AuthResponse, error) {
	logger.Info("Starting registration", "email", input.Email)

	if len(input.Name) < 3 {
		logger.Warn("Name too short", "name_length", len(input.Name))
		return nil, apperr.ErrNameTooShort
	}

	if input.Password != input.PasswordConfirm {
		logger.Warn("Password mismatch")
		return nil, apperr.ErrPasswordMismatch
	}

	if !s.isValidPassword(input.Password) {
		logger.Warn("Weak password")
		return nil, apperr.ErrWeakPassword
	}

	existingUser, _ := s.repo.GetByEmail(ctx, input.Email)
	if existingUser != nil {
		logger.Warn("User already exists", "email", input.Email)
		return nil, apperr.ErrUserAlreadyExists
	}

	hashedPassword, err := s.hashPassword(input.Password)
	if err != nil {
		logger.Error("Failed to hash password", "error", err)
		return nil, apperr.ErrInternalServer
	}

	user, err := s.repo.Create(ctx, domain.CreateUserParams{
		Name:     input.Name,
		Email:    input.Email,
		Password: hashedPassword,
		Role:     string(domain.Customer),
	})
	if err != nil {
		logger.Error("Failed to create user", "error", err)
		return nil, apperr.ErrInternalServer
	}

	otp := s.generateOTP()
	expiresAt := time.Now().Add(time.Duration(s.otpExpiryMins) * time.Minute).Format(time.RFC3339)

	_, err = s.repo.SetEmailOTP(ctx, user.ID.String(), otp, expiresAt, s.otpMaxAttempts)
	if err != nil {
		logger.Error("Failed to set email OTP", "error", err)
		return nil, apperr.ErrInternalServer
	}

	if err := s.emailSender.SendEmailOTP(ctx, input.Email, otp); err != nil {
		logger.Error("Failed to send email OTP", "error", err)
		return nil, err
	}

	token, err := s.tokenMaker.CreateToken(&models.TokenUser{
		ID:   user.ID.String(),
		Name: user.Name,
		Role: string(user.Role),
	}, s.accessDuration)
	if err != nil {
		logger.Error("Failed to create token", "error", err)
		return nil, apperr.ErrInternalServer
	}

	logger.Info("Registration completed", "user_id", user.ID)
	return &domain.AuthResponse{
		User:  user,
		Token: token,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, input domain.LoginInput) (*domain.AuthResponse, error) {
	logger.Info("Starting login", "email", input.Email)

	user, err := s.repo.GetByEmail(ctx, input.Email)
	if err != nil {
		logger.Warn("User not found", "email", input.Email)
		return nil, apperr.ErrInvalidPassword
	}

	if !s.verifyPassword(user.Password, input.Password) {
		logger.Warn("Invalid password", "email", input.Email)
		return nil, apperr.ErrInvalidPassword
	}

	token, err := s.tokenMaker.CreateToken(&models.TokenUser{
		ID:   user.ID.String(),
		Name: user.Name,
		Role: string(user.Role),
	}, s.accessDuration)
	if err != nil {
		logger.Error("Failed to create token", "error", err)
		return nil, apperr.ErrInternalServer
	}

	logger.Info("Login successful", "user_id", user.ID)
	return &domain.AuthResponse{
		User:  user,
		Token: token,
	}, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, userID, otp string) (*domain.User, error) {
	logger.Info("Verifying email", "user_id", userID)

	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		logger.Warn("User not found", "user_id", userID)
		return nil, apperr.ErrUserNotFound
	}

	if user.EmailOtp == nil || *user.EmailOtp != otp {
		attemptsRemaining := s.decrementAttempts(ctx, user, true)
		logger.Warn("Invalid OTP", "user_id", userID, "attempts_remaining", attemptsRemaining)
		return nil, errors.New(apperr.ErrInvalidOTP.Error() + "; attempts_remaining=" + string(rune('0'+attemptsRemaining)))
	}

	if user.EmailOtpExpiresAt != nil && time.Now().After(*user.EmailOtpExpiresAt) {
		logger.Warn("OTP expired", "user_id", userID)
		return nil, apperr.ErrOTPExpired
	}

	updatedUser, err := s.repo.ClearEmailOTP(ctx, userID)
	if err != nil {
		logger.Error("Failed to clear email OTP", "error", err)
		return nil, apperr.ErrInternalServer
	}

	logger.Info("Email verified", "user_id", userID)
	return updatedUser, nil
}

func (s *AuthService) SendEmailOTP(ctx context.Context, userID string) error {
	logger.Info("Sending email OTP", "user_id", userID)

	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		logger.Warn("User not found", "user_id", userID)
		return apperr.ErrUserNotFound
	}

	otp := s.generateOTP()
	expiresAt := time.Now().Add(time.Duration(s.otpExpiryMins) * time.Minute).Format(time.RFC3339)

	_, err = s.repo.SetEmailOTP(ctx, userID, otp, expiresAt, s.otpMaxAttempts)
	if err != nil {
		logger.Error("Failed to set email OTP", "error", err)
		return apperr.ErrInternalServer
	}

	if err := s.emailSender.SendEmailOTP(ctx, user.Email, otp); err != nil {
		logger.Error("Failed to send email OTP", "error", err)
		return err
	}

	logger.Info("Email OTP sent", "user_id", userID)
	return nil
}

func (s *AuthService) SendPhoneOTP(ctx context.Context, userID, phone, countryCode string) error {
	logger.Info("Sending phone OTP", "user_id", userID, "phone", phone)

	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		logger.Warn("User not found", "user_id", userID)
		return apperr.ErrUserNotFound
	}

	otp := s.generateOTP()
	expiresAt := time.Now().Add(time.Duration(s.otpExpiryMins) * time.Minute).Format(time.RFC3339)

	fullPhone := countryCode + phone

	_, err = s.repo.SetPhoneOTP(ctx, userID, otp, expiresAt, s.otpMaxAttempts)
	if err != nil {
		logger.Error("Failed to set phone OTP", "error", err)
		return apperr.ErrInternalServer
	}

	_, err = s.repo.Update(ctx, domain.UpdateUserParams{
		ID:               userID,
		Name:             user.Name,
		Email:            user.Email,
		Phone:            &fullPhone,
		PhoneCountryCode: &countryCode,
		Role:             string(user.Role),
		IsEmailVerified:  user.IsEmailVerified,
		IsPhoneVerified:  false,
	})
	if err != nil {
		logger.Error("Failed to update user phone", "error", err)
		return apperr.ErrInternalServer
	}

	if err := s.phoneSender.SendPhoneOTP(ctx, fullPhone, otp); err != nil {
		logger.Error("Failed to send phone OTP", "error", err)
		return err
	}

	logger.Info("Phone OTP sent", "user_id", userID)
	return nil
}

func (s *AuthService) VerifyPhone(ctx context.Context, userID, otp string) (*domain.User, error) {
	logger.Info("Verifying phone", "user_id", userID)

	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		logger.Warn("User not found", "user_id", userID)
		return nil, apperr.ErrUserNotFound
	}

	if user.PhoneOtp == nil || *user.PhoneOtp != otp {
		attemptsRemaining := s.decrementAttempts(ctx, user, false)
		logger.Warn("Invalid OTP", "user_id", userID, "attempts_remaining", attemptsRemaining)
		return nil, errors.New(apperr.ErrInvalidOTP.Error() + "; attempts_remaining=" + string(rune('0'+attemptsRemaining)))
	}

	if user.PhoneOtpExpiresAt != nil && time.Now().After(*user.PhoneOtpExpiresAt) {
		logger.Warn("OTP expired", "user_id", userID)
		return nil, apperr.ErrOTPExpired
	}

	updatedUser, err := s.repo.ClearPhoneOTP(ctx, userID)
	if err != nil {
		logger.Error("Failed to clear phone OTP", "error", err)
		return nil, apperr.ErrInternalServer
	}

	logger.Info("Phone verified", "user_id", userID)
	return updatedUser, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*domain.User, error) {
	return s.repo.GetByID(ctx, userID)
}

func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.repo.GetByEmail(ctx, email)
}

func (s *AuthService) RegisterGoogleUser(ctx context.Context, email, name, imageURL string) (*domain.User, error) {
	logger.Info("Registering Google user", "email", email)

	existingUser, _ := s.repo.GetByEmail(ctx, email)
	if existingUser != nil {
		logger.Info("Google user already exists", "email", email)
		return existingUser, nil
	}

	user, err := s.repo.Create(ctx, domain.CreateUserParams{
		Name:     name,
		Email:    email,
		Password: "google-oauth",
		Role:     string(domain.Customer),
	})
	if err != nil {
		logger.Error("Failed to create Google user", "error", err)
		return nil, apperr.ErrInternalServer
	}

	if imageURL != "" {
		s.repo.Update(ctx, domain.UpdateUserParams{
			ID:              user.ID.String(),
			Name:            user.Name,
			Email:           user.Email,
			ImagePath:       &imageURL,
			Role:            string(user.Role),
			IsEmailVerified: true,
			IsPhoneVerified: false,
		})
	}

	logger.Info("Google user registered", "user_id", user.ID)
	return user, nil
}

func (s *AuthService) CreateSessionToken(ctx context.Context, userID string, duration time.Duration) (string, error) {
	logger.Info("Creating session token", "user_id", userID)

	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		logger.Error("Failed to get user", "error", err)
		return "", err
	}

	return s.tokenMaker.CreateToken(&models.TokenUser{
		ID:   user.ID.String(),
		Name: user.Name,
		Role: string(user.Role),
	}, duration)
}

func (s *AuthService) UpdateUserRole(ctx context.Context, userID, role string) (*domain.User, error) {
	logger.Info("Updating user role", "user_id", userID, "role", role)
	return s.repo.UpdateRole(ctx, userID, role)
}

func (s *AuthService) generateOTP() string {
	b := make([]byte, 3)
	rand.Read(b)
	return hex.EncodeToString(b)[:6]
}

func (s *AuthService) isValidPassword(password string) bool {
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial && len(password) >= 6
}

func (s *AuthService) hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	encoded := hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash)
	return encoded, nil
}

func (s *AuthService) verifyPassword(stored, input string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 2 {
		return false
	}

	salt, _ := hex.DecodeString(parts[0])
	hash, _ := hex.DecodeString(parts[1])

	computedHash := argon2.IDKey([]byte(input), salt, 1, 64*1024, 4, 32)

	return string(computedHash) == string(hash)
}

func (s *AuthService) decrementAttempts(ctx context.Context, user *domain.User, isEmail bool) int {
	var attempts int
	if isEmail {
		attempts = user.EmailOtpAttempts - 1
		if attempts < 0 {
			attempts = 0
		}
		expiresAt := time.Now().Add(time.Duration(s.otpExpiryMins) * time.Minute).Format(time.RFC3339)
		s.repo.SetEmailOTP(ctx, user.ID.String(), *user.EmailOtp, expiresAt, attempts)
	} else {
		attempts = user.PhoneOtpAttempts - 1
		if attempts < 0 {
			attempts = 0
		}
		expiresAt := time.Now().Add(time.Duration(s.otpExpiryMins) * time.Minute).Format(time.RFC3339)
		s.repo.SetPhoneOTP(ctx, user.ID.String(), *user.PhoneOtp, expiresAt, attempts)
	}
	return attempts
}
