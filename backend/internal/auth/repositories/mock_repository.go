package repositories

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/suryansh74/subway-luxe/internal/auth/domain"
)

type MockUserRepository struct {
	mu      sync.Mutex
	users   map[string]*domain.User
	byEmail map[string]*domain.User
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:   make(map[string]*domain.User),
		byEmail: make(map[string]*domain.User),
	}
}

func (m *MockUserRepository) Create(ctx context.Context, arg domain.CreateUserParams) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user := &domain.User{
		ID:              uuid.New(),
		Name:            arg.Name,
		Email:           arg.Email,
		Password:        arg.Password,
		Role:            domain.Role(arg.Role),
		IsEmailVerified: false,
		IsPhoneVerified: false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	m.users[user.ID.String()] = user
	m.byEmail[user.Email] = user

	return user, nil
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if user, ok := m.byEmail[email]; ok {
		return user, nil
	}
	return nil, domain.ErrUserNotFound
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if user, ok := m.users[id]; ok {
		return user, nil
	}
	return nil, domain.ErrUserNotFound
}

func (m *MockUserRepository) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

func (m *MockUserRepository) Update(ctx context.Context, arg domain.UpdateUserParams) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[arg.ID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	if arg.Name != "" {
		user.Name = arg.Name
	}
	if arg.Email != "" {
		user.Email = arg.Email
	}
	if arg.Phone != nil {
		user.Phone = arg.Phone
	}
	if arg.PhoneCountryCode != nil {
		user.PhoneCountryCode = arg.PhoneCountryCode
	}
	if arg.ImagePath != nil {
		user.ImagePath = arg.ImagePath
	}
	if arg.Role != "" {
		user.Role = domain.Role(arg.Role)
	}
	if arg.Address != nil {
		user.Address = arg.Address
	}
	user.IsEmailVerified = arg.IsEmailVerified
	user.IsPhoneVerified = arg.IsPhoneVerified
	user.UpdatedAt = time.Now()

	return user, nil
}

func (m *MockUserRepository) SetEmailOTP(ctx context.Context, userID string, otp string, expiresAt string, attempts int) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	user.EmailOtp = &otp
	user.EmailOtpAttempts = attempts
	// Parse and set expiresAt
	if expiresAt != "" {
		expTime, _ := time.Parse(time.RFC3339, expiresAt)
		user.EmailOtpExpiresAt = &expTime
	}

	return user, nil
}

func (m *MockUserRepository) SetPhoneOTP(ctx context.Context, userID string, otp string, expiresAt string, attempts int) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	user.PhoneOtp = &otp
	user.PhoneOtpAttempts = attempts
	if expiresAt != "" {
		expTime, _ := time.Parse(time.RFC3339, expiresAt)
		user.PhoneOtpExpiresAt = &expTime
	}

	return user, nil
}

func (m *MockUserRepository) ClearEmailOTP(ctx context.Context, userID string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	user.EmailOtp = nil
	user.EmailOtpExpiresAt = nil
	user.EmailOtpAttempts = 0
	user.IsEmailVerified = true
	user.UpdatedAt = time.Now()

	return user, nil
}

func (m *MockUserRepository) ClearPhoneOTP(ctx context.Context, userID string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	user.PhoneOtp = nil
	user.PhoneOtpExpiresAt = nil
	user.PhoneOtpAttempts = 0
	user.IsPhoneVerified = true
	user.UpdatedAt = time.Now()

	return user, nil
}

func (m *MockUserRepository) UpdateRole(ctx context.Context, userID string, role string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	user.Role = domain.Role(role)
	user.UpdatedAt = time.Now()

	return user, nil
}
