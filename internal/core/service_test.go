package core

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/models"
)

type MockDB struct {
	GetUserFunc              func(email string) (*models.User, error)
	CreateUserFunc           func(user *models.User) error
	StoreRefreshTokenFunc    func(token *models.RefreshToken) error
	ValidateRefreshTokenFunc func(email, token string) (bool, error)
}

func (m *MockDB) GetUser(email string) (*models.User, error) {
	if m.GetUserFunc != nil {
		return m.GetUserFunc(email)
	}
	return nil, nil
}

func (m *MockDB) CreateUser(user *models.User) error {
	if m.CreateUserFunc != nil {
		return m.CreateUserFunc(user)
	}
	return nil
}

func (m *MockDB) StoreRefreshToken(token *models.RefreshToken) error {
	if m.StoreRefreshTokenFunc != nil {
		return m.StoreRefreshTokenFunc(token)
	}
	return nil
}

func (m *MockDB) ValidateRefreshToken(email, token string) (bool, error) {
	if m.ValidateRefreshTokenFunc != nil {
		return m.ValidateRefreshTokenFunc(email, token)
	}
	return true, nil
}

func TestRegisterService(t *testing.T) {
	t.Run("Successful Registration", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return nil, nil
			},
			CreateUserFunc: func(user *models.User) error {
				return nil
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		accessToken, refreshToken, err := svc.Register("test@example.com", "password")
		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("Database Error on GetUser", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return nil, errors.New("database error")
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Register("test@example.com", "password")
		assert.EqualError(t, err, "database error")
	})

	t.Run("Database Error on CreateUser", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return nil, nil
			},
			CreateUserFunc: func(user *models.User) error {
				return errors.New("database error")
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Register("test@example.com", "password")
		assert.EqualError(t, err, "database error")
	})

	t.Run("Database Error on StoreRefreshToken", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return nil, nil
			},
			CreateUserFunc: func(user *models.User) error {
				return nil
			},
			StoreRefreshTokenFunc: func(token *models.RefreshToken) error {
				return errors.New("database error")
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Register("test@example.com", "password")
		assert.EqualError(t, err, "database error")
	})
}

func TestLoginService(t *testing.T) {
	t.Run("Successful Login", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return &models.User{
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}, nil
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		accessToken, refreshToken, err := svc.Login("test@example.com", "password")
		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("User Not Found", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return nil, nil
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Login("test@example.com", "password")
		assert.EqualError(t, err, "invalid credentials")
	})

	t.Run("Database Error", func(t *testing.T) {
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return nil, errors.New("database error")
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Login("test@example.com", "password")
		assert.EqualError(t, err, "database error")
	})

	t.Run("Invalid Password", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct_password"), bcrypt.DefaultCost)
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return &models.User{
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}, nil
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Login("test@example.com", "wrong_password")
		assert.EqualError(t, err, "invalid credentials")
	})

	t.Run("Error Storing Refresh Token", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mockDB := &MockDB{
			GetUserFunc: func(email string) (*models.User, error) {
				return &models.User{
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}, nil
			},
			StoreRefreshTokenFunc: func(token *models.RefreshToken) error {
				return errors.New("database error")
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err := svc.Login("test@example.com", "password")
		assert.EqualError(t, err, "failed to store refresh token in database")
	})
}

func TestRefreshTokenService(t *testing.T) {
	t.Run("Valid Refresh Token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
		})
		validToken, err := token.SignedString([]byte("refreshSecret"))
		require.NoError(t, err)

		mockDB := &MockDB{
			ValidateRefreshTokenFunc: func(email, token string) (bool, error) {
				return true, nil
			},
			StoreRefreshTokenFunc: func(token *models.RefreshToken) error {
				return nil
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		accessToken, refreshToken, err := svc.RefreshToken(validToken)
		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
		})
		invalidToken, err := token.SignedString([]byte("wrongSecret"))
		require.NoError(t, err)

		mockDB := &MockDB{
			ValidateRefreshTokenFunc: func(email, token string) (bool, error) {
				return false, nil
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err = svc.RefreshToken(invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})

	t.Run("Error Validating Refresh Token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
		})
		validToken, err := token.SignedString([]byte("refreshSecret"))
		require.NoError(t, err)

		mockDB := &MockDB{
			ValidateRefreshTokenFunc: func(email, token string) (bool, error) {
				return false, errors.New("database error")
			},
		}
		svc := NewService(mockDB, "secret", "refreshSecret")

		_, _, err = svc.RefreshToken(validToken)
		assert.EqualError(t, err, "no refresh token found")
	})
}

func TestValidateAccessTokenService(t *testing.T) {
	t.Run("Valid Token", func(t *testing.T) {
		svc := NewService(&MockDB{}, "secret", "refreshSecret")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(15 * time.Minute).Unix(),
		})
		validToken, _ := token.SignedString([]byte("secret"))

		email, err := svc.ValidateAccessToken(validToken)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", email)
	})

	t.Run("Expired Token", func(t *testing.T) {
		svc := NewService(&MockDB{}, "secret", "refreshSecret")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(-15 * time.Minute).Unix(), // expired
		})
		expiredToken, _ := token.SignedString([]byte("secret"))

		_, err := svc.ValidateAccessToken(expiredToken)
		assert.Error(t, err)
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		svc := NewService(&MockDB{}, "secret", "refreshSecret")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(15 * time.Minute).Unix(),
		})
		invalidToken, _ := token.SignedString([]byte("wrong_secret"))

		_, err := svc.ValidateAccessToken(invalidToken)
		assert.Error(t, err)
	})

	t.Run("Missing Email Claim", func(t *testing.T) {
		svc := NewService(&MockDB{}, "secret", "refreshSecret")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(15 * time.Minute).Unix(),
		})
		tokenString, _ := token.SignedString([]byte("secret"))

		_, err := svc.ValidateAccessToken(tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token claims")
	})

	t.Run("Malformed Token", func(t *testing.T) {
		svc := NewService(&MockDB{}, "secret", "refreshSecret")
		_, err := svc.ValidateAccessToken("not.a.jwt")
		assert.Error(t, err)
	})
}

func TestRegisterWithExistingUserService(t *testing.T) {
	// Mock the database
	mockDB := &MockDB{
		GetUserFunc: func(email string) (*models.User, error) {
			return &models.User{
				Email:    "test@example.com",
				Password: "hashed-password",
			}, nil
		},
	}
	svc := NewService(mockDB, "secret", "refreshSecret")

	_, _, err := svc.Register("test@example.com", "password")
	assert.EqualError(t, err, "email already registered")
}

func TestLoginWithInvalidCredentialsService(t *testing.T) {
	mockDB := &MockDB{
		GetUserFunc: func(email string) (*models.User, error) {
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
			return &models.User{
				Email:    "test@example.com",
				Password: string(hashedPassword),
			}, nil
		},
	}
	svc := NewService(mockDB, "secret", "refreshSecret")

	_, _, err := svc.Login("test@example.com", "wrong-password")
	assert.EqualError(t, err, "invalid credentials")
}
