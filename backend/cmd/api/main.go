package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/suryansh74/subway-luxe/config"
	"github.com/suryansh74/subway-luxe/pkg/logger"
	"github.com/suryansh74/subway-luxe/server"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "development"
	}

	if err := logger.InitWithPath(cfg.LogPath, logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, fmt.Sprintf("postgres://%s:%s@%s:%s/%s", cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName))
	if err != nil {
		logger.Fatal("Unable to create pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	logger.Info("Database pool created successfully")

	srv := server.NewServer(&cfg, pool)
	srv.Start()
}
