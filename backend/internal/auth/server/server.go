package server

import (
	"github.com/go-chi/chi"
	"github.com/jackc/pgx/v5"
	"github.com/suryansh74/subway-luxe/internal/auth/config"
	"github.com/suryansh74/zomato/services/shared/token"
)

type server struct {
	cfg            *config.Config
	router         *chi.Mux
	postgresClient *pgx.Conn
	tokenMaker     token.Maker
}
