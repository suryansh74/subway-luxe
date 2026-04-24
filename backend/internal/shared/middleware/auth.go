package middleware

import (
	"context"
	"net/http"

	"github.com/suryansh74/subway-luxe/internal/shared/token"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
	UserIDKey      contextKey = "user_id"
)

func AuthMiddleware(tokenMaker token.Maker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_token")
			if err != nil {
				http.Error(w, `{"error": "unauthorized: session cookie missing"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := cookie.Value

			payload, err := tokenMaker.VerifyToken(tokenStr)
			if err != nil {
				http.Error(w, `{"error": "unauthorized: invalid session"}`, http.StatusUnauthorized)
				return
			}

			userID := payload.User.ID

			ctx := context.WithValue(r.Context(), UserContextKey, payload)
			ctx = context.WithValue(ctx, UserIDKey, userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func VerificationMiddleware(verifyEmail, verifyPhone bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !verifyEmail && !verifyPhone {
				next.ServeHTTP(w, r)
				return
			}

			userID := r.Context().Value(UserIDKey)
			if userID == nil {
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			type VerifiableUser struct {
				IsEmailVerified bool `json:"is_email_verified"`
				IsPhoneVerified bool `json:"is_phone_verified"`
			}

			userVal := r.Context().Value("verified_user")
			if userVal == nil {
				http.Error(w, `{"error": "user data not found"}`, http.StatusInternalServerError)
				return
			}
			user := userVal.(*VerifiableUser)

			if verifyEmail && !user.IsEmailVerified {
				http.Error(w, `{"error": "email verification required", "code": "EMAIL_NOT_VERIFIED"}`, http.StatusForbidden)
				return
			}

			if verifyPhone && !user.IsPhoneVerified {
				http.Error(w, `{"error": "phone verification required", "code": "PHONE_NOT_VERIFIED"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
