package models

import "time"

type User struct {
	ID         string    `json:"id" dynamodbav:"id"`
	Email      string    `json:"email" dynamodbav:"email"`
	Name       string    `json:"name" dynamodbav:"name"`
	Password   string    `json:"-" dynamodbav:"password"`
	IsAdmin    bool      `json:"isAdmin" dynamodbav:"isAdmin"`
	ApiCalls   int       `json:"apiCalls" dynamodbav:"api_calls"`
	CreatedAt  time.Time `json:"createdAt" dynamodbav:"created_at"`
	LastActive time.Time `json:"lastActive" dynamodbav:"last_active"`
}

type RefreshToken struct {
	UserID    string    `json:"user_id" dynamodbav:"user_id"`
	Token     string    `json:"token" dynamodbav:"token"`
	ExpiresAt time.Time `json:"expires_at" dynamodbav:"expires_at"`
}
