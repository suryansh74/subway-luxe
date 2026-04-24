package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Host                string        `mapstructure:"SERVER_HOST"`
	Port                string        `mapstructure:"SERVER_PORT"`
	PostgressURI        string        `mapstructure:"POSTGRESS_URI"`
	DBName              string        `mapstructure:"DB_NAME"`
	CollectionName      string        `mapstructure:"COLLECTION_NAME"`
	TokenSymmetricKey   string        `mapstructure:"TOKEN_SYMMETRIC_KEY"`
	AccessTokenDuration time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	GoogleClientID      string        `mapstructure:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret  string        `mapstructure:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURL   string        `mapstructure:"GOOGLE_REDIRECT_URL"`
	IsDev               bool          `mapstructure:"IS_DEV"`
	FrontendURL         string        `mapstructure:"FRONTEND_URL"`
}

func LoadConfig() (config Config, err error) {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err = viper.ReadInConfig(); err != nil {
		return config, fmt.Errorf("failed to read config: %w", err)
	}

	err = viper.Unmarshal(&config)
	return config, err
}
