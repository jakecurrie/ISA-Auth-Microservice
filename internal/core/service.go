package core

import (
	"errors"
	"time"

	"auth-service/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Database interface {
	GetUser(email string) (*models.User, error)
	CreateUser(user *models.User) error
	StoreRefreshToken(token *models.RefreshToken) error
	ValidateRefreshToken(email, token string) (bool, error)
}

type ServiceImpl struct {
	db            Database
	jwtSecret     []byte
	refreshSecret []byte
}

func NewService(db Database, jwtSecret, refreshSecret string) *ServiceImpl {
	return &ServiceImpl{
		db:            db,
		jwtSecret:     []byte(jwtSecret),
		refreshSecret: []byte(refreshSecret),
	}
}

func (svc *ServiceImpl) Register(email, password string) (string, string, error) {
	existing, err := svc.db.GetUser(email)
	if err != nil {
		return "", "", err
	}
	if existing != nil {
		return "", "", errors.New("email already registered")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	err = svc.db.CreateUser(&models.User{
		Email:    email,
		Password: string(hashedPassword),
	})
	if err != nil {
		return "", "", err
	}

	accessToken, err := svc.createAccessToken(email)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := svc.createRefreshToken(email)
	if err != nil {
		return "", "", err
	}

	err = svc.db.StoreRefreshToken(&models.RefreshToken{
		Email:     email,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (svc *ServiceImpl) Login(email, password string) (string, string, error) {
	user, err := svc.db.GetUser(email)
	if err != nil {
		return "", "", err
	}
	if user == nil {
		return "", "", errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", "", errors.New("invalid credentials")
	}

	accessToken, err := svc.createAccessToken(email)
	if err != nil {
		return "", "", errors.New("failed to create access token")
	}

	refreshToken, err := svc.createRefreshToken(email)
	if err != nil {
		return "", "", errors.New("failed to create refresh token")
	}

	err = svc.db.StoreRefreshToken(&models.RefreshToken{
		Email:     email,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return "", "", errors.New("failed to store refresh token in database")
	}

	return accessToken, refreshToken, nil
}

func (svc *ServiceImpl) RefreshToken(refreshToken string) (string, string, error) {
	email, err := svc.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", "", errors.New("invalid refresh token")
	}

	valid, err := svc.db.ValidateRefreshToken(email, refreshToken)
	if err != nil || !valid {
		return "", "", errors.New("no refresh token found")
	}

	accessToken, err := svc.createAccessToken(email)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := svc.createRefreshToken(email)
	if err != nil {
		return "", "", err
	}

	err = svc.db.StoreRefreshToken(&models.RefreshToken{
		Email:     email,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

func (svc *ServiceImpl) ValidateAccessToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return svc.jwtSecret, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email, ok := claims["email"].(string)
		if !ok {
			return "", errors.New("invalid token claims")
		}
		return email, nil
	}

	return "", errors.New("invalid token")
}

func (svc *ServiceImpl) createAccessToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	return token.SignedString(svc.jwtSecret)
}

func (svc *ServiceImpl) createRefreshToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(7 * 24 * time.Hour).Unix(),
	})
	return token.SignedString(svc.refreshSecret)
}

func (svc *ServiceImpl) ValidateRefreshToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return svc.refreshSecret, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email, ok := claims["email"].(string)
		if !ok {
			return "", errors.New("invalid token claims")
		}
		return email, nil
	}

	return "", errors.New("invalid refresh token")
}
