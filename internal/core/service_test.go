package core

import (
	"errors"
	"testing"
	"time"

	"auth-service/internal/middleware"
	"auth-service/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type MockDB struct {
	GetUserByEmailFunc       func(email string) (*models.User, error)
	GetUserByIDFunc          func(id string) (*models.User, error)
	CreateUserFunc           func(user *models.User) error
	StoreRefreshTokenFunc    func(token *models.RefreshToken) error
	ValidateRefreshTokenFunc func(userID, token string) (bool, error)
	UpdateLastActiveFunc     func(userID string) error
	GetAllUsersFunc          func() ([]models.User, error)
}

func (m *MockDB) GetUserByEmail(email string) (*models.User, error) {
	if m.GetUserByEmailFunc == nil {
		return nil, nil
	}
	return m.GetUserByEmailFunc(email)
}

func (m *MockDB) GetUserByID(id string) (*models.User, error) {
	if m.GetUserByIDFunc == nil {
		return nil, nil
	}
	return m.GetUserByIDFunc(id)
}

func (m *MockDB) CreateUser(user *models.User) error {
	if m.CreateUserFunc == nil {
		return nil
	}
	return m.CreateUserFunc(user)
}

func (m *MockDB) StoreRefreshToken(token *models.RefreshToken) error {
	if m.StoreRefreshTokenFunc == nil {
		return nil
	}
	return m.StoreRefreshTokenFunc(token)
}

func (m *MockDB) ValidateRefreshToken(userID, token string) (bool, error) {
	if m.ValidateRefreshTokenFunc == nil {
		return true, nil
	}
	return m.ValidateRefreshTokenFunc(userID, token)
}

func (m *MockDB) UpdateLastActive(userID string) error {
	if m.UpdateLastActiveFunc == nil {
		return nil
	}
	return m.UpdateLastActiveFunc(userID)
}

func (m *MockDB) GetAllUsers() ([]models.User, error) {
	if m.GetAllUsersFunc == nil {
		return nil, nil
	}
	return m.GetAllUsersFunc()
}

func setupMockDB() *MockDB {
	return &MockDB{
		GetUserByEmailFunc: func(email string) (*models.User, error) {
			return nil, nil
		},
		GetUserByIDFunc: func(id string) (*models.User, error) {
			return nil, nil
		},
		CreateUserFunc: func(user *models.User) error {
			return nil
		},
		StoreRefreshTokenFunc: func(token *models.RefreshToken) error {
			return nil
		},
		ValidateRefreshTokenFunc: func(userID, token string) (bool, error) {
			return true, nil
		},
		UpdateLastActiveFunc: func(userID string) error {
			return nil
		},
	}
}

func TestRegisterService(t *testing.T) {
	t.Run("Successful Registration", func(t *testing.T) {
		mockDB := setupMockDB()
		mockDB.GetUserByEmailFunc = func(email string) (*models.User, error) {
			return nil, nil
		}
		mockDB.CreateUserFunc = func(user *models.User) error {
			assert.NotEmpty(t, user.ID)
			assert.Equal(t, "test@example.com", user.Email)
			assert.Equal(t, "Test User", user.Name)
			assert.NotEmpty(t, user.Password)
			return nil
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Register("test@example.com", "password", "Test User")
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.NotEmpty(t, response.User.ID)
		assert.Equal(t, "test@example.com", response.User.Email)
		assert.Equal(t, "Test User", response.User.Name)
	})

	t.Run("Email Already Exists", func(t *testing.T) {
		mockDB := setupMockDB()
		mockDB.GetUserByEmailFunc = func(email string) (*models.User, error) {
			return &models.User{
				ID:    "existing-id",
				Email: email,
				Name:  "Existing User",
			}, nil
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Register("test@example.com", "password", "Test User")
		assert.Nil(t, response)
		assert.Error(t, err)
		assert.Equal(t, "email already registered", err.Error())
	})

	t.Run("Database Error", func(t *testing.T) {
		mockDB := setupMockDB()
		mockDB.GetUserByEmailFunc = func(email string) (*models.User, error) {
			return nil, errors.New("database error")
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Register("test@example.com", "password", "Test User")
		assert.Nil(t, response)
		assert.Error(t, err)
		assert.Equal(t, "database error", err.Error())
	})
}

func TestLoginService(t *testing.T) {
	t.Run("Successful Login", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mockDB := &MockDB{
			GetUserByEmailFunc: func(email string) (*models.User, error) {
				return &models.User{
					ID:       "test-id",
					Email:    "test@example.com",
					Name:     "Test User",
					Password: string(hashedPassword),
				}, nil
			},
			StoreRefreshTokenFunc: func(token *models.RefreshToken) error {
				return nil
			},
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Login("test@example.com", "password")
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "test-id", response.User.ID)
	})

	t.Run("Invalid Password", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
		mockDB := &MockDB{
			GetUserByEmailFunc: func(email string) (*models.User, error) {
				return &models.User{
					ID:       "test-id",
					Email:    email,
					Password: string(hashedPassword),
				}, nil
			},
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Login("test@example.com", "wrong-password")
		assert.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())
		assert.Nil(t, response)
	})

	t.Run("User Not Found", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserByEmailFunc: func(email string) (*models.User, error) {
				return nil, nil
			},
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Login("test@example.com", "password")
		assert.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())
		assert.Nil(t, response)
	})

	t.Run("Database Error", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserByEmailFunc: func(email string) (*models.User, error) {
				return nil, errors.New("database error")
			},
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		response, err := svc.Login("test@example.com", "password")
		assert.Error(t, err)
		assert.Equal(t, "database error", err.Error())
		assert.Nil(t, response)
	})
}

func TestRefreshTokenService(t *testing.T) {
	mockUser := &models.User{
		ID:    "test-id",
		Role:  "user",
		Email: "test@example.com",
		Name:  "Test User",
	}

	createValidRefreshToken := func(secret []byte, userID, userRole string) string {
		token, _ := middleware.CreateToken(userID, userRole, secret, 24*time.Hour)
		return token
	}

	t.Run("Successful Refresh", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserByIDFunc: func(id string) (*models.User, error) {
				assert.Equal(t, mockUser.ID, id)
				return mockUser, nil
			},
			ValidateRefreshTokenFunc: func(userID, token string) (bool, error) {
				return true, nil
			},
			StoreRefreshTokenFunc: func(token *models.RefreshToken) error {
				assert.Equal(t, mockUser.ID, token.UserID)
				assert.NotEmpty(t, token.Token)
				return nil
			},
		}

		svc := NewService(mockDB, "jwt-secret", "refresh-secret")
		refreshToken := createValidRefreshToken([]byte("refresh-secret"), mockUser.ID, mockUser.Role)

		response, err := svc.RefreshToken(refreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, mockUser.ID, response.User.ID)
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		mockDB := &MockDB{}
		svc := NewService(mockDB, "jwt-secret", "refresh-secret")

		invalidToken := "invalid-token"
		response, err := svc.RefreshToken(invalidToken)
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})

	t.Run("Expired Refresh Token", func(t *testing.T) {
		mockDB := &MockDB{}
		svc := NewService(mockDB, "jwt-secret", "refresh-secret")

		expiredToken, _ := middleware.CreateToken(
			mockUser.ID,
			mockUser.Role,
			[]byte("refresh-secret"),
			-1*time.Hour,
		)

		response, err := svc.RefreshToken(expiredToken)
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})

	t.Run("User Not Found", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserByIDFunc: func(id string) (*models.User, error) {
				return nil, nil
			},
			ValidateRefreshTokenFunc: func(userID, token string) (bool, error) {
				return true, nil
			},
		}

		svc := NewService(mockDB, "jwt-secret", "refresh-secret")
		refreshToken := createValidRefreshToken([]byte("refresh-secret"), mockUser.ID, mockUser.Role)

		response, err := svc.RefreshToken(refreshToken)
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "user not found")
	})

	t.Run("Database Error", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserByIDFunc: func(id string) (*models.User, error) {
				return nil, errors.New("database error")
			},
		}

		svc := NewService(mockDB, "jwt-secret", "refresh-secret")
		refreshToken := createValidRefreshToken([]byte("refresh-secret"), mockUser.ID, mockUser.Role)

		response, err := svc.RefreshToken(refreshToken)
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "failed to get user")
	})

	t.Run("Invalid Stored Token", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserByIDFunc: func(id string) (*models.User, error) {
				return mockUser, nil
			},
			ValidateRefreshTokenFunc: func(userID, token string) (bool, error) {
				return false, nil
			},
		}

		svc := NewService(mockDB, "jwt-secret", "refresh-secret")
		refreshToken := createValidRefreshToken([]byte("refresh-secret"), mockUser.ID, mockUser.Role)

		response, err := svc.RefreshToken(refreshToken)
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})
}

func TestMeService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockDB := setupMockDB()
		mockDB.GetUserByIDFunc = func(id string) (*models.User, error) {
			return &models.User{
				ID:    id,
				Email: "test@example.com",
				Name:  "Test User",
			}, nil
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		user, err := svc.Me("test-id")
		require.NoError(t, err)
		assert.Equal(t, "test-id", user.ID)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test User", user.Name)
	})

	t.Run("User Not Found", func(t *testing.T) {
		mockDB := setupMockDB()
		mockDB.GetUserByIDFunc = func(id string) (*models.User, error) {
			return nil, errors.New("user not found")
		}

		svc := NewService(mockDB, "secret", "refreshSecret")

		_, err := svc.Me("test-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}
