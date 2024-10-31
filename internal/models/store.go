package models

import "time"

type User struct {
	Email    string `dynamodbav:"email"`
	Password string `dynamodbav:"password"`
}

type RefreshToken struct {
	Email     string    `dynamodbav:"email"`
	Token     string    `dynamodbav:"token"`
	ExpiresAt time.Time `dynamodbav:"expires_at"`
}
