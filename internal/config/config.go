package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerAddress  string
	DatabaseURL    string
	JWTSecret      string
	GoogleClientID string
	GoogleClientSecret string
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	return &Config{
		ServerAddress:  os.Getenv("SERVER_ADDRESS"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		JWTSecret:      os.Getenv("JWT_SECRET"),
		GoogleClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	}, nil
}