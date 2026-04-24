package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/suryansh74/subway-luxe/config"
	"github.com/suryansh74/subway-luxe/internal/auth/handlers"
	"github.com/suryansh74/subway-luxe/internal/auth/infrastructure/adapters"
	"github.com/suryansh74/subway-luxe/internal/auth/repositories"
	"github.com/suryansh74/subway-luxe/internal/auth/services"
	authMiddleware "github.com/suryansh74/subway-luxe/internal/shared/middleware"
	"github.com/suryansh74/subway-luxe/internal/shared/models"
	"github.com/suryansh74/subway-luxe/internal/shared/token"
	"github.com/suryansh74/subway-luxe/pkg/logger"

	swaggerFiles "github.com/swaggo/http-swagger/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type serviceTokenMaker struct {
	maker token.Maker
}

func (s *serviceTokenMaker) CreateToken(user *models.TokenUser, duration time.Duration) (string, error) {
	return s.maker.CreateToken(user, duration)
}

func (s *serviceTokenMaker) VerifyToken(tokenStr string) (*models.TokenUser, error) {
	payload, err := s.maker.VerifyToken(tokenStr)
	if err != nil {
		return nil, err
	}
	return payload.User, nil
}

type server struct {
	cfg        *config.Config
	router     *chi.Mux
	pool       *pgxpool.Pool
	tokenMaker token.Maker
}

func NewServer(cfg *config.Config, pool *pgxpool.Pool) *server {
	tokenMaker, err := token.NewPasetoMaker(cfg.TokenSymmetricKey)
	if err != nil {
		logger.Fatal("Failed to create token maker", "error", err)
		panic(err)
	}
	logger.Info("Token maker created successfully")
	return &server{
		cfg:        cfg,
		router:     chi.NewRouter(),
		pool:       pool,
		tokenMaker: tokenMaker,
	}
}

func (s *server) Start() {
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{s.cfg.FrontendURL},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	s.setupRoutes()

	if s.cfg.EnableSwaggerUI {
		logger.Info("Enabling Swagger UI")
		s.router.Handle("/api/docs/*", http.StripPrefix("/api/docs", swaggerFiles.Handler()))
	}

	addr := s.cfg.Host + ":" + s.cfg.Port
	logger.Info("Server starting", "address", addr)
	if err := http.ListenAndServe(addr, s.router); err != nil {
		logger.Fatal("Server failed to start", "error", err)
	}
}

func (s *server) setupRoutes() {
	logger.Info("Setting up routes")

	emailSender := adapters.NewEmailSender(
		s.cfg.SMTPHost,
		s.cfg.SMTPPort,
		s.cfg.SMTPUsername,
		s.cfg.SMTPPassword,
	)

	phoneSender := adapters.NewPhoneSender(
		s.cfg.TwilioAccountSid,
		s.cfg.TwilioAuthToken,
		s.cfg.TwilioMessagingServiceSid,
	)

	authRepo := repositories.NewAuthRepository(s.pool)

	sm := &serviceTokenMaker{maker: s.tokenMaker}

	authService := services.NewAuthService(
		authRepo,
		emailSender,
		phoneSender,
		sm,
		s.cfg.AccessTokenDuration,
		s.cfg.OtpExpiryMinutes,
		s.cfg.OtpMaxAttempts,
	)
	authHandler := handlers.NewAuthHandler(
		authService,
		sm,
		s.cfg.AccessTokenDuration,
		s.cfg.CookieMaxAge,
		s.cfg.CookieSameSite,
		s.cfg.FrontendURL,
		s.getOAuthConfig(),
	)

	s.router.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	s.router.Post("/api/auth/register", authHandler.Register)
	s.router.Post("/api/auth/login", authHandler.Login)
	s.router.Post("/api/auth/logout", authHandler.Logout)
	s.router.Get("/api/auth/google/login", authHandler.LoginGoogle)
	s.router.Get("/api/auth/google/callback", authHandler.GoogleCallback)

	s.router.Group(func(r chi.Router) {
		r.Use(authMiddleware.AuthMiddleware(s.tokenMaker))
		r.Post("/api/auth/verify-email", authHandler.VerifyEmail)
		r.Post("/api/auth/send-email-otp", authHandler.SendEmailOTP)
		r.Post("/api/auth/send-phone-otp", authHandler.SendPhoneOTP)
		r.Post("/api/auth/verify-phone", authHandler.VerifyPhone)
		r.Get("/api/auth/profile", authHandler.Profile)
		r.Post("/api/auth/add-role", authHandler.AddRole)
	})

	logger.Info("Routes setup complete")
}

func (s *server) getOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.cfg.GoogleClientID,
		ClientSecret: s.cfg.GoogleClientSecret,
		RedirectURL:  s.cfg.GoogleRedirectURL,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}
}
