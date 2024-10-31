package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-service/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockService struct {
	RegisterFunc             func(email, password string) (string, string, error)
	LoginFunc                func(email, password string) (string, string, error)
	RefreshTokenFunc         func(refreshToken string) (string, string, error)
	ValidateAccessTokenFunc  func(token string) (string, error)
	ValidateRefreshTokenFunc func(token string) (string, error)
}

func (m *MockService) Register(email, password string) (string, string, error) {
	return m.RegisterFunc(email, password)
}

func (m *MockService) Login(email, password string) (string, string, error) {
	return m.LoginFunc(email, password)
}

func (m *MockService) RefreshToken(refreshToken string) (string, string, error) {
	return m.RefreshTokenFunc(refreshToken)
}

func (m *MockService) ValidateAccessToken(token string) (string, error) {
	return m.ValidateAccessTokenFunc(token)
}

func (m *MockService) ValidateRefreshToken(token string) (string, error) {
	return m.ValidateRefreshTokenFunc(token)
}

func TestRegisterHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockSvc := &MockService{
			RegisterFunc: func(email, password string) (string, string, error) {
				return "access_token", "refresh_token", nil
			},
		}
		handler := NewHandler(mockSvc)

		body := models.RegisterRequest{
			Email:    "test@example.com",
			Password: "password",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Register(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)

		var response models.TokenResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "access_token", response.AccessToken)
		assert.Equal(t, "refresh_token", response.RefreshToken)
	})

	t.Run("Invalid Request Body", func(t *testing.T) {
		handler := NewHandler(&MockService{})

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("invalid json"))
		rr := httptest.NewRecorder()

		handler.Register(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestLoginHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockSvc := &MockService{
			LoginFunc: func(email, password string) (string, string, error) {
				return "access_token", "refresh_token", nil
			},
		}
		handler := NewHandler(mockSvc)

		body := models.LoginRequest{
			Email:    "test@example.com",
			Password: "password",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Login(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)

		var response models.TokenResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "access_token", response.AccessToken)
		assert.Equal(t, "refresh_token", response.RefreshToken)
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		mockSvc := &MockService{
			LoginFunc: func(email, password string) (string, string, error) {
				return "", "", errors.New("invalid credentials")
			},
		}
		handler := NewHandler(mockSvc)

		body := models.LoginRequest{
			Email:    "test@example.com",
			Password: "wrong_password",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Login(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestValidateTokenHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockSvc := &MockService{
			ValidateAccessTokenFunc: func(token string) (string, error) {
				return "test@example.com", nil
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/validate", nil)
		req.Header.Set("Authorization", "Bearer valid_token")
		rr := httptest.NewRecorder()

		handler.ValidateToken(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)

		var response models.ValidateResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", response.Email)
	})

	t.Run("No Token", func(t *testing.T) {
		handler := NewHandler(&MockService{})

		req := httptest.NewRequest(http.MethodGet, "/validate", nil)
		rr := httptest.NewRecorder()

		handler.ValidateToken(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		mockSvc := &MockService{
			ValidateAccessTokenFunc: func(token string) (string, error) {
				return "", errors.New("invalid token")
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/validate", nil)
		req.Header.Set("Authorization", "Bearer invalid_token")
		rr := httptest.NewRecorder()

		handler.ValidateToken(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
