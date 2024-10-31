package config

import "os"

type Config struct {
	JWTSecret     string
	RefreshSecret string
	UsersTable    string
	TokensTable   string
}

func Load() *Config {
	return &Config{
		JWTSecret:     os.Getenv("JWT_SECRET"),
		RefreshSecret: os.Getenv("REFRESH_SECRET"),
		UsersTable:    os.Getenv("USERS_TABLE"),
		TokensTable:   os.Getenv("TOKENS_TABLE"),
	}
}
