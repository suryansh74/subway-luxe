package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/suryansh74/subway-luxe/internal/auth/domain"
	"github.com/suryansh74/subway-luxe/internal/auth/infrastructure/adapters"
	"github.com/suryansh74/subway-luxe/internal/auth/repositories"
	"github.com/suryansh74/subway-luxe/internal/auth/services"
	"github.com/suryansh74/subway-luxe/internal/shared/middleware"
	"github.com/suryansh74/subway-luxe/internal/shared/models"
	"github.com/suryansh74/subway-luxe/pkg/logger"
)

func init() {
	logger.Init("development")
}

type mockHandlerTokenMaker struct {
	tokens map[string]string
}

func (m *mockHandlerTokenMaker) CreateToken(user *models.TokenUser, duration time.Duration) (string, error) {
	token := "mock-token-" + user.ID
	m.tokens[token] = user.ID
	return token, nil
}

func (m *mockHandlerTokenMaker) VerifyToken(token string) (*models.TokenUser, error) {
	if userID, ok := m.tokens[token]; ok {
		return &models.TokenUser{ID: userID}, nil
	}
	return nil, domain.ErrInvalidPassword
}

func setupTestHandler() (*AuthHandler, *repositories.MockUserRepository, *adapters.MockEmailSender, *adapters.MockPhoneSender) {
	repo := repositories.NewMockUserRepository()
	emailSender := adapters.NewMockEmailSender()
	phoneSender := adapters.NewMockPhoneSender()
	tokenMaker := &mockHandlerTokenMaker{tokens: make(map[string]string)}

	service := services.NewAuthService(repo, emailSender, phoneSender, tokenMaker, time.Hour, 15, 3)

	handler := NewAuthHandler(service, tokenMaker, time.Hour, 7200, "lax", "http://localhost:3000", nil)

	return handler, repo, emailSender, phoneSender
}

func TestHandler_Register(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	body := map[string]interface{}{
		"name":             "John Doe",
		"email":            "john@example.com",
		"password":         "Password1!",
		"password_confirm": "Password1!",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Contains(t, resp, "user")
	assert.Contains(t, resp, "message")
}

func TestHandler_Register_InvalidBody(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_Register_PasswordMismatch(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	body := map[string]interface{}{
		"name":             "John Doe",
		"email":            "john@example.com",
		"password":         "Password1!",
		"password_confirm": "Password2!",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "PASSWORD_MISMATCH")
}

func TestHandler_Login(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	// First register a user
	registerBody := map[string]interface{}{
		"name":             "John Doe",
		"email":            "john@example.com",
		"password":         "Password1!",
		"password_confirm": "Password1!",
	}
	registerBytes, _ := json.Marshal(registerBody)
	registerReq := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(registerBytes))
	registerReq.Header.Set("Content-Type", "application/json")
	registerW := httptest.NewRecorder()
	handler.Register(registerW, registerReq)

	// Now try to login
	loginBody := map[string]interface{}{
		"email":    "john@example.com",
		"password": "Password1!",
	}
	loginBytes, _ := json.Marshal(loginBody)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code) // Because email not verified

	// Check for cookie
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "session_token", cookies[0].Name)
}

func TestHandler_Login_InvalidCredentials(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	body := map[string]interface{}{
		"email":    "nonexistent@example.com",
		"password": "Password1!",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_CREDENTIALS")
}

func TestHandler_Logout(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	w := httptest.NewRecorder()

	handler.Logout(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "session_token", cookies[0].Name)
	assert.True(t, cookies[0].Expires.Before(time.Now()))
}

func TestHandler_VerifyEmail(t *testing.T) {
	handler, _, emailSender, _ := setupTestHandler()

	registerBody := map[string]interface{}{
		"name":             "John Doe",
		"email":            "john@example.com",
		"password":         "Password1!",
		"password_confirm": "Password1!",
	}
	registerBytes, _ := json.Marshal(registerBody)
	registerReq := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(registerBytes))
	registerReq.Header.Set("Content-Type", "application/json")
	registerW := httptest.NewRecorder()
	handler.Register(registerW, registerReq)

	var registerResp map[string]interface{}
	json.Unmarshal(registerW.Body.Bytes(), &registerResp)
	userMap := registerResp["user"].(map[string]interface{})
	userID := userMap["id"].(string)

	otp := emailSender.SentOTPs["john@example.com"]

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, userID)

	verifyBody := map[string]interface{}{
		"otp": otp,
	}
	verifyBytes, _ := json.Marshal(verifyBody)
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/auth/verify-email", bytes.NewReader(verifyBytes))
	verifyReq = verifyReq.WithContext(ctx)
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyW := httptest.NewRecorder()

	handler.VerifyEmail(verifyW, verifyReq)

	assert.Equal(t, http.StatusOK, verifyW.Code)

	var verifyResp map[string]interface{}
	json.Unmarshal(verifyW.Body.Bytes(), &verifyResp)
	assert.Contains(t, verifyResp, "user")
}

func TestHandler_Profile_WithAuth(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	registerBody := map[string]interface{}{
		"name":             "John Doe",
		"email":            "john@example.com",
		"password":         "Password1!",
		"password_confirm": "Password1!",
	}
	registerBytes, _ := json.Marshal(registerBody)
	registerReq := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(registerBytes))
	registerReq.Header.Set("Content-Type", "application/json")
	registerW := httptest.NewRecorder()
	handler.Register(registerW, registerReq)

	var registerResp map[string]interface{}
	json.Unmarshal(registerW.Body.Bytes(), &registerResp)
	userMap := registerResp["user"].(map[string]interface{})
	userID := userMap["id"].(string)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/profile", nil)
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Profile(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var profileResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &profileResp)
	assert.Equal(t, "john@example.com", profileResp["email"])
	assert.Equal(t, "John Doe", profileResp["name"])
}
