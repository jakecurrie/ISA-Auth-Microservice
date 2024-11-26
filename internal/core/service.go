package core

import (
	"errors"
	"fmt"
	"log"
	"time"

	"auth-service/internal/middleware"
	"auth-service/internal/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
)

type Database interface {
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	StoreRefreshToken(token *models.RefreshToken) error
	ValidateRefreshToken(userID, token string) (bool, error)
	UpdateLastActive(userID string) error
	GetAllUsers() ([]models.User, error)
	DeleteUser(userID string) error
	UpdateUserName(userID string, name string) error
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

func (s *ServiceImpl) Register(email, password, name string) (*models.AuthResponse, error) {
	log.Printf("Starting registration for email: %s", email)

	existingUser, err := s.db.GetUserByEmail(email)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		return nil, err
	}
	if existingUser != nil {
		log.Printf("User already exists with email: %s", email)
		return nil, errors.New("email already registered")
	}

	log.Printf("Creating new user with email: %s", email)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return nil, err
	}

	user := &models.User{
		ID:         uuid.New().String(),
		Email:      email,
		Name:       name,
		Password:   string(hashedPassword),
		IsAdmin:    false,
		ApiCalls:   0,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	log.Printf("Attempting to create user in database with ID: %s", user.ID)
	if err := s.db.CreateUser(user); err != nil {
		log.Printf("Error creating user in database: %v", err)
		return nil, err
	}

	log.Printf("User created successfully, generating auth response")
	return s.generateAuthResponse(user)
}

func (s *ServiceImpl) Login(email, password string) (*models.AuthResponse, error) {
	user, err := s.db.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	return s.generateAuthResponse(user)
}

func (s *ServiceImpl) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	claims, err := middleware.VerifyToken(refreshToken, s.refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	user, err := s.db.GetUserByID(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	valid, err := s.db.ValidateRefreshToken(claims.UserID, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}
	if !valid {
		return nil, errors.New("invalid refresh token")
	}

	newAccessToken, err := middleware.CreateToken(
		user.ID,
		user.IsAdmin,
		s.jwtSecret,
		15*time.Minute,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	newRefreshToken, err := middleware.CreateToken(
		user.ID,
		user.IsAdmin,
		s.refreshSecret,
		7*24*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	err = s.db.StoreRefreshToken(&models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &models.AuthResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		User:         user,
	}, nil
}

func (s *ServiceImpl) Me(userID string) (*models.User, error) {
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	err = s.db.UpdateLastActive(userID)
	if err != nil {
		log.Printf("Failed to update last active: %v", err)
		return user, fmt.Errorf("failed to update last active: %w", err)
	}

	return user, nil
}

func (s *ServiceImpl) generateAuthResponse(user *models.User) (*models.AuthResponse, error) {
	accessToken, err := middleware.CreateToken(
		user.ID,
		user.IsAdmin,
		s.jwtSecret,
		15*time.Minute,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	refreshToken, err := middleware.CreateToken(
		user.ID,
		user.IsAdmin,
		s.refreshSecret,
		7*24*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	err = s.db.StoreRefreshToken(&models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *ServiceImpl) GetAllUsers(isAdmin bool) ([]models.User, error) {
	if !isAdmin {
		return nil, errors.New("unauthorized: admin access required")
	}

	users, err := s.db.GetAllUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	return users, nil
}

func (s *ServiceImpl) DeleteAccount(userID string) error {
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("failed to verify user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	if err := s.db.DeleteUser(userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

func (s *ServiceImpl) UpdateUserName(userID string, name string) error {
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("failed to verify user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	if name == "" {
		return errors.New("name cannot be empty")
	}

	if err := s.db.UpdateUserName(userID, name); err != nil {
		return fmt.Errorf("failed to update user name: %w", err)
	}

	return nil
}
