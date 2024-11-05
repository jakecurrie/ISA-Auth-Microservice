package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-service/internal/middleware"
	"auth-service/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockService struct {
	RegisterFunc     func(email, password, name string) (*models.AuthResponse, error)
	LoginFunc        func(email, password string) (*models.AuthResponse, error)
	RefreshTokenFunc func(refreshToken string) (*models.AuthResponse, error)
	MeFunc           func(userID string) (*models.User, error)
	GetAllUsersFunc  func(role string) ([]models.User, error)
}

func (m *MockService) Register(email, password, name string) (*models.AuthResponse, error) {
	return m.RegisterFunc(email, password, name)
}

func (m *MockService) Login(email, password string) (*models.AuthResponse, error) {
	return m.LoginFunc(email, password)
}

func (m *MockService) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	return m.RefreshTokenFunc(refreshToken)
}

func (m *MockService) Me(userID string) (*models.User, error) {
	return m.MeFunc(userID)
}

func (m *MockService) GetAllUsers(role string) ([]models.User, error) {
	return m.GetAllUsersFunc(role)
}

func TestRegisterHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockSvc := &MockService{
			RegisterFunc: func(email, password, name string) (*models.AuthResponse, error) {
				assert.Equal(t, "test@example.com", email)
				assert.Equal(t, "password123", password)
				assert.Equal(t, "Test User", name)

				return &models.AuthResponse{
					AccessToken:  "access_token",
					RefreshToken: "refresh_token",
					User: &models.User{
						ID:    "test-id",
						Email: email,
						Name:  name,
					},
				}, nil
			},
		}
		handler := NewHandler(mockSvc)

		body := models.RegisterRequest{
			Email:    "test@example.com",
			Password: "password123",
			Name:     "Test User",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Register(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

		var response models.AuthResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.NotEmpty(t, response.User.ID)
		assert.Equal(t, "test@example.com", response.User.Email)
		assert.Equal(t, "Test User", response.User.Name)
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		handler := NewHandler(&MockService{})

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("invalid json"))
		rr := httptest.NewRecorder()

		handler.Register(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Missing Required Fields", func(t *testing.T) {
		handler := NewHandler(&MockService{})

		testCases := []struct {
			name string
			body models.RegisterRequest
		}{
			{
				name: "Missing Email",
				body: models.RegisterRequest{
					Password: "password123",
					Name:     "Test User",
				},
			},
			{
				name: "Missing Password",
				body: models.RegisterRequest{
					Email: "test@example.com",
					Name:  "Test User",
				},
			},
			{
				name: "Missing Name",
				body: models.RegisterRequest{
					Email:    "test@example.com",
					Password: "password123",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				bodyBytes, _ := json.Marshal(tc.body)
				req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(bodyBytes))
				rr := httptest.NewRecorder()

				handler.Register(rr, req)

				assert.Equal(t, http.StatusBadRequest, rr.Code)
			})
		}
	})

	t.Run("Email Already Exists", func(t *testing.T) {
		mockSvc := &MockService{
			RegisterFunc: func(email, password, name string) (*models.AuthResponse, error) {
				return nil, errors.New("email already registered")
			},
		}
		handler := NewHandler(mockSvc)

		body := models.RegisterRequest{
			Email:    "existing@example.com",
			Password: "password123",
			Name:     "Test User",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Register(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestLoginHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockSvc := &MockService{
			LoginFunc: func(email, password string) (*models.AuthResponse, error) {
				assert.Equal(t, "test@example.com", email)
				assert.Equal(t, "password123", password)

				return &models.AuthResponse{
					AccessToken:  "access_token",
					RefreshToken: "refresh_token",
					User: &models.User{
						ID:    "test-id",
						Email: email,
						Name:  "Test User",
					},
				}, nil
			},
		}
		handler := NewHandler(mockSvc)

		body := models.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Login(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

		var response models.AuthResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "test-id", response.User.ID)
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		mockSvc := &MockService{
			LoginFunc: func(email, password string) (*models.AuthResponse, error) {
				return nil, errors.New("invalid credentials")
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

	t.Run("Missing Required Fields", func(t *testing.T) {
		mockSvc := &MockService{
			LoginFunc: func(email, password string) (*models.AuthResponse, error) {
				t.Fatal("LoginFunc should not be called with invalid request")
				return nil, nil
			},
		}
		handler := NewHandler(mockSvc)

		testCases := []struct {
			name string
			body interface{}
		}{
			{
				name: "Missing Email",
				body: models.LoginRequest{
					Password: "password123",
				},
			},
			{
				name: "Missing Password",
				body: models.LoginRequest{
					Email: "test@example.com",
				},
			},
			{
				name: "Empty Request",
				body: models.LoginRequest{},
			},
			{
				name: "Invalid JSON",
				body: "invalid json",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var bodyBytes []byte
				var err error

				if str, ok := tc.body.(string); ok {
					bodyBytes = []byte(str)
				} else {
					bodyBytes, err = json.Marshal(tc.body)
					require.NoError(t, err)
				}

				req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(bodyBytes))
				rr := httptest.NewRecorder()

				handler.Login(rr, req)

				assert.Equal(t, http.StatusBadRequest, rr.Code)
			})
		}
	})

	t.Run("Service Error", func(t *testing.T) {
		mockSvc := &MockService{
			LoginFunc: func(email, password string) (*models.AuthResponse, error) {
				return nil, errors.New("service error")
			},
		}
		handler := NewHandler(mockSvc)

		body := models.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(bodyBytes))
		rr := httptest.NewRecorder()

		handler.Login(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestRefreshHandler(t *testing.T) {
	mockUser := &models.User{
		ID:    "test-id",
		Email: "test@example.com",
		Name:  "Test User",
	}

	t.Run("Successful Refresh", func(t *testing.T) {
		mockSvc := &MockService{
			RefreshTokenFunc: func(refreshToken string) (*models.AuthResponse, error) {
				return &models.AuthResponse{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					User:         mockUser,
				}, nil
			},
		}

		handler := NewHandler(mockSvc)
		req := models.RefreshRequest{
			RefreshToken: "valid-refresh-token",
		}
		body, _ := json.Marshal(req)

		r := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		handler.Refresh(w, r)

		require.Equal(t, http.StatusOK, w.Code)

		var response models.AuthResponse
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, mockUser.ID, response.User.ID)
	})

	t.Run("Invalid Request Body", func(t *testing.T) {
		handler := NewHandler(&MockService{})
		r := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBufferString("invalid json"))
		w := httptest.NewRecorder()

		handler.Refresh(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Missing Refresh Token", func(t *testing.T) {
		handler := NewHandler(&MockService{})
		req := models.RefreshRequest{
			RefreshToken: "",
		}
		body, _ := json.Marshal(req)

		r := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		handler.Refresh(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		mockSvc := &MockService{
			RefreshTokenFunc: func(refreshToken string) (*models.AuthResponse, error) {
				return nil, errors.New("invalid refresh token")
			},
		}

		handler := NewHandler(mockSvc)
		req := models.RefreshRequest{
			RefreshToken: "invalid-token",
		}
		body, _ := json.Marshal(req)

		r := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		handler.Refresh(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestMeHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		expectedUser := &models.User{
			ID:    "test-id",
			Email: "test@example.com",
			Name:  "Test User",
		}

		mockSvc := &MockService{
			MeFunc: func(userID string) (*models.User, error) {
				assert.Equal(t, "test-id", userID)
				return expectedUser, nil
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		claims := &models.Claims{
			UserID: "test-id",
			Role:   "user",
		}
		req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
		rr := httptest.NewRecorder()

		handler.Me(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

		var response models.User
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, expectedUser.ID, response.ID)
		assert.Equal(t, expectedUser.Email, response.Email)
		assert.Equal(t, expectedUser.Name, response.Name)
	})

	t.Run("No Claims in Context", func(t *testing.T) {
		mockSvc := &MockService{
			MeFunc: func(userID string) (*models.User, error) {
				t.Fatal("Service should not be called when claims are missing")
				return nil, nil
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		rr := httptest.NewRecorder()

		handler.Me(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Empty UserID in Claims", func(t *testing.T) {
		mockSvc := &MockService{
			MeFunc: func(userID string) (*models.User, error) {
				t.Fatal("Service should not be called with empty user ID")
				return nil, nil
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		claims := &models.Claims{
			UserID: "",
			Role:   "user",
		}
		req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
		rr := httptest.NewRecorder()

		handler.Me(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("User Not Found", func(t *testing.T) {
		mockSvc := &MockService{
			MeFunc: func(userID string) (*models.User, error) {
				return nil, errors.New("user not found")
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		claims := &models.Claims{
			UserID: "test-id",
			Role:   "user",
		}
		req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
		rr := httptest.NewRecorder()

		handler.Me(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "user not found")
	})

	t.Run("Service Error", func(t *testing.T) {
		mockSvc := &MockService{
			MeFunc: func(userID string) (*models.User, error) {
				return nil, errors.New("service error")
			},
		}
		handler := NewHandler(mockSvc)

		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		claims := &models.Claims{
			UserID: "test-id",
			Role:   "user",
		}
		req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
		rr := httptest.NewRecorder()

		handler.Me(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), "service error")
	})
}
