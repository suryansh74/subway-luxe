package middleware

import (
	"context"
	"net/http"

	"github.com/suryansh74/zomato/services/shared/helper"
	"github.com/suryansh74/zomato/services/shared/token"
)

type contextKey string

const UserContextKey contextKey = "user"

func AuthMiddleware(tokenMaker token.Maker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// read cookie
			cookie, err := r.Cookie("session_token")
			if err != nil {
				helper.WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "unauthorized: session cookie missing",
				})
				return
			}

			tokenStr := cookie.Value

			// verify paseto token
			payload, err := tokenMaker.VerifyToken(tokenStr)
			if err != nil {
				helper.WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "unauthorized: invalid session",
				})
				return
			}

			// store payload inside request context
			ctx := context.WithValue(r.Context(), UserContextKey, payload)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
