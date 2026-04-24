// @title        Subway Luxe API
// @version      1.0
// @description  API Documentation for Subway Luxe Authentication
// @host         localhost:8080
// @BasePath     /api
// @securityDefinitions.appres BearerAuth
// @description Authorization header using JWT
// @security
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/suryansh74/subway-luxe/internal/auth/domain"
	"github.com/suryansh74/subway-luxe/internal/auth/services"
	"github.com/suryansh74/subway-luxe/internal/shared/middleware"
	"github.com/suryansh74/subway-luxe/pkg/logger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AuthHandler struct {
	service        *services.AuthService
	tokenMaker     services.TokenMaker
	accessDuration time.Duration
	cookieMaxAge   int
	cookieSameSite string
	frontendURL    string
	oauthConfig    *oauth2.Config
}

func NewAuthHandler(
	service *services.AuthService,
	tokenMaker services.TokenMaker,
	accessDuration time.Duration,
	cookieMaxAge int,
	cookieSameSite string,
	frontendURL string,
	oauthConfig *oauth2.Config,
) *AuthHandler {
	if oauthConfig == nil {
		oauthConfig = &oauth2.Config{
			ClientID:     "",
			ClientSecret: "",
			RedirectURL:  "",
			Scopes:       []string{"email", "profile"},
			Endpoint:     google.Endpoint,
		}
	}
	return &AuthHandler{
		service:        service,
		tokenMaker:     tokenMaker,
		accessDuration: accessDuration,
		cookieMaxAge:   cookieMaxAge,
		cookieSameSite: cookieSameSite,
		frontendURL:    frontendURL,
		oauthConfig:    oauthConfig,
	}
}

// Register	新規ユーザー登録
// @Summary		Register new user
// @Description	Register a new user with name, email and password. An OTP will be sent to email for verification.
// @Tags		auth
// @Accept		json
// @Produce		json
// @Param		register body domain.RegisterInput true "Register request"
// @Success		201 {object} map[string]interface{}
// @Failure		400 {object} map[string]string
// @Failure		409 {object} map[string]string
// @Router		/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input domain.RegisterInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Warn("Invalid request body", "error", err)
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	logger.Info("Processing registration", "email", input.Email)

	resp, err := h.service.Register(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.setCookie(w, resp.Token)
	h.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"user":    resp.User,
		"message": "OTP sent to email for verification",
	})

	logger.Info("Registration successful", "user_id", resp.User.ID)
}

// Login	ユーザーログイン
// @Summary		User login
// @Description	Login with email and password. Returns user info and sets session cookie.
// @Tags		auth
// @Accept		json
// @Produce		json
// @Param		login body domain.LoginInput true "Login request"
// @Success		200 {object} map[string]interface{}
// @Success		403 {object} map[string]string "Email or phone verification required"
// @Failure		401 {object} map[string]string
// @Router		/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input domain.LoginInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Warn("Invalid request body", "error", err)
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	logger.Info("Processing login", "email", input.Email)

	resp, err := h.service.Login(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.setCookie(w, resp.Token)

	status := http.StatusOK
	message := "login successful"
	code := ""

	if !resp.User.IsEmailVerified {
		status = http.StatusForbidden
		message = "email verification required"
		code = "EMAIL_NOT_VERIFIED"
	} else if !resp.User.IsPhoneVerified {
		status = http.StatusForbidden
		message = "phone verification required"
		code = "PHONE_NOT_VERIFIED"
	}

	h.writeJSON(w, status, map[string]interface{}{
		"user":    resp.User,
		"message": message,
		"code":    code,
	})

	logger.Info("Login successful", "user_id", resp.User.ID)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		SameSite: h.getSameSite(),
	})

	h.writeJSON(w, http.StatusOK, map[string]string{
		"message": "logged out successfully",
	})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value(middleware.UserIDKey)
	if userIDVal == nil {
		logger.Error("userID is nil in context")
		http.Error(w, `{"error": "unauthorized: user not in context"}`, http.StatusUnauthorized)
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		logger.Error("userID is wrong type", "type", fmt.Sprintf("%T", userIDVal))
		http.Error(w, `{"error": "internal error: wrong type"}`, http.StatusInternalServerError)
		return
	}

	var input domain.VerifyEmailInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Warn("Invalid request body", "error", err)
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	logger.Info("Verifying email", "user_id", userID)

	user, err := h.service.VerifyEmail(r.Context(), userID, input.Otp)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":    user,
		"message": "email verified successfully",
	})
}

func (h *AuthHandler) SendEmailOTP(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value(middleware.UserIDKey)
	userID, _ := userIDVal.(string)

	logger.Info("Sending email OTP", "user_id", userID)

	if err := h.service.SendEmailOTP(r.Context(), userID); err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{
		"message": "OTP sent to email",
	})
}

func (h *AuthHandler) SendPhoneOTP(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value(middleware.UserIDKey)
	userID, _ := userIDVal.(string)

	var input domain.SendPhoneOtpInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Warn("Invalid request body", "error", err)
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	logger.Info("Sending phone OTP", "user_id", userID, "phone", input.Phone)

	if err := h.service.SendPhoneOTP(r.Context(), userID, input.Phone, input.PhoneCountryCode); err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{
		"message": "OTP sent to phone",
	})
}

func (h *AuthHandler) VerifyPhone(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value(middleware.UserIDKey)
	userID, _ := userIDVal.(string)

	var input domain.VerifyPhoneInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Warn("Invalid request body", "error", err)
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	logger.Info("Verifying phone", "user_id", userID)

	user, err := h.service.VerifyPhone(r.Context(), userID, input.Otp)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":    user,
		"message": "phone verified successfully",
	})
}

func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value(middleware.UserIDKey)
	userID, _ := userIDVal.(string)

	user, err := h.service.GetUserByID(r.Context(), userID)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":                 user.ID,
		"name":               user.Name,
		"email":              user.Email,
		"phone":              user.Phone,
		"phone_country_code": user.PhoneCountryCode,
		"role":               user.Role,
		"is_email_verified":  user.IsEmailVerified,
		"is_phone_verified":  user.IsPhoneVerified,
		"created_at":         user.CreatedAt,
		"updated_at":         user.UpdatedAt,
	})
}

func (h *AuthHandler) AddRole(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value(middleware.UserIDKey)
	userID, _ := userIDVal.(string)

	var input struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Warn("Invalid request body", "error", err)
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	logger.Info("Adding role", "user_id", userID, "role", input.Role)

	user, err := h.service.UpdateUserRole(r.Context(), userID, input.Role)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, user)
}

func (h *AuthHandler) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	url := h.oauthConfig.AuthCodeURL("random-state-string")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Warn("Google OAuth code missing")
		http.Error(w, `{"error": "code not found"}`, http.StatusBadRequest)
		return
	}

	token, err := h.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		logger.Error("Failed to exchange OAuth token", "error", err)
		http.Error(w, `{"error": "failed to exchange token"}`, http.StatusInternalServerError)
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		logger.Error("Failed to get user info", "error", err)
		http.Error(w, `{"error": "failed to get user info"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		logger.Error("Failed to decode user info", "error", err)
		http.Error(w, `{"error": "failed to decode user info"}`, http.StatusInternalServerError)
		return
	}

	logger.Info("Processing Google callback", "email", googleUser.Email)

	user, err := h.service.GetUserByEmail(r.Context(), googleUser.Email)
	if err != nil {
		user, err = h.service.RegisterGoogleUser(r.Context(), googleUser.Email, googleUser.Name, googleUser.Picture)
		if err != nil {
			h.writeError(w, err)
			return
		}
	}

	sessionToken, err := h.service.CreateSessionToken(r.Context(), user.ID.String(), h.accessDuration)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.setCookie(w, sessionToken)

	status := http.StatusOK
	message := "login successful"
	codeStr := ""

	if !user.IsEmailVerified {
		status = http.StatusForbidden
		message = "email verification required"
		codeStr = "EMAIL_NOT_VERIFIED"
	} else if !user.IsPhoneVerified {
		status = http.StatusForbidden
		message = "phone verification required"
		codeStr = "PHONE_NOT_VERIFIED"
	}

	h.writeJSON(w, status, map[string]interface{}{
		"user":    user,
		"message": message,
		"code":    codeStr,
	})
}

func (h *AuthHandler) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  time.Now().Add(h.accessDuration),
		HttpOnly: true,
		SameSite: h.getSameSite(),
	})
}

func (h *AuthHandler) getSameSite() http.SameSite {
	switch h.cookieSameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func (h *AuthHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) writeError(w http.ResponseWriter, err error) {
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "user already exists"):
		logger.Warn("User already exists", "error", errStr)
		http.Error(w, `{"error": "user already exists", "code": "USER_EXISTS"}`, http.StatusConflict)
		return
	case strings.Contains(errStr, "invalid credentials"), strings.Contains(errStr, "invalid password"):
		logger.Warn("Invalid credentials", "error", errStr)
		http.Error(w, `{"error": "invalid credentials", "code": "INVALID_CREDENTIALS"}`, http.StatusUnauthorized)
		return
	case strings.Contains(errStr, "at least 3 characters"):
		logger.Warn("Name too short", "error", errStr)
		http.Error(w, `{"error": "name must be at least 3 characters", "code": "NAME_TOO_SHORT"}`, http.StatusBadRequest)
		return
	case strings.Contains(errStr, "passwords do not match"):
		logger.Warn("Password mismatch", "error", errStr)
		http.Error(w, `{"error": "passwords do not match", "code": "PASSWORD_MISMATCH"}`, http.StatusBadRequest)
		return
	case strings.Contains(errStr, "password must contain"):
		logger.Warn("Weak password", "error", errStr)
		http.Error(w, `{"error": "password must contain at least one uppercase letter, one number, and one special character", "code": "WEAK_PASSWORD"}`, http.StatusBadRequest)
		return
	case strings.Contains(errStr, "invalid OTP"):
		logger.Warn("Invalid OTP", "error", errStr)
		http.Error(w, `{"error": "invalid OTP", "code": "INVALID_OTP"}`, http.StatusBadRequest)
		return
	case strings.Contains(errStr, "OTP has expired"):
		logger.Warn("OTP expired", "error", errStr)
		http.Error(w, `{"error": "OTP has expired", "code": "OTP_EXPIRED"}`, http.StatusBadRequest)
		return
	case strings.Contains(errStr, "user not found"):
		logger.Warn("User not found", "error", errStr)
		http.Error(w, `{"error": "user not found", "code": "USER_NOT_FOUND"}`, http.StatusNotFound)
		return
	case strings.Contains(errStr, "internal server error"):
		logger.Error("Internal server error", "error", errStr)
		http.Error(w, `{"error": "internal server error", "code": "INTERNAL_ERROR"}`, http.StatusInternalServerError)
		return
	}

	logger.Error("Unknown error", "error", errStr)
	http.Error(w, `{"error": "`+errStr+`", "code": "UNKNOWN_ERROR"}`, http.StatusInternalServerError)
}
