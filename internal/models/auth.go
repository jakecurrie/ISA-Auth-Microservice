package models

import "github.com/golang-jwt/jwt/v5"

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type ValidateResponse struct {
	Email string `json:"email"`
}

type AuthResponse struct {
	User *User `json:"user"`
	// Internal fields, not JSON encoded
	AccessToken  string `json:"-"`
	RefreshToken string `json:"-"`
}

type Claims struct {
	UserID  string `json:"userId"`
	IsAdmin bool   `json:"isAdmin"`
	jwt.RegisteredClaims
}
