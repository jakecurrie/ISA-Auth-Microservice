package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"auth-service/internal/models"
)

type contextKey string

const (
	ClaimsKey contextKey = "claims"
	UserIDKey contextKey = "userId"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
	ErrMissingToken = errors.New("missing token")
)

func VerifyToken(tokenString string, secret []byte) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.UserID == "" {
		return nil, errors.New("missing user ID claim")
	}

	return claims, nil
}

func CreateToken(userID string, isAdmin bool, secret []byte, expiration time.Duration) (string, error) {
	claims := models.Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func AuthMiddleware(jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			cookie, err := r.Cookie("access_token")
			if err != nil {
				if r.URL.Path == "/auth/refresh" {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			claims, err := VerifyToken(cookie.Value, jwtSecret)
			if err != nil {
				switch {
				case errors.Is(err, ErrExpiredToken):
					http.SetCookie(w, &http.Cookie{
						Name:     "access_token",
						Value:    "",
						Path:     "/",
						Domain:   "",
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteNoneMode,
						MaxAge:   -1,
					})
					http.Error(w, "token expired", http.StatusUnauthorized)
				default:
					http.Error(w, "unauthorized", http.StatusUnauthorized)
				}
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
