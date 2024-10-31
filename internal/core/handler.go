package core

import (
	"encoding/json"
	"net/http"

	"auth-service/internal/models"
)

type Service interface {
	Register(email, password string) (string, string, error)
	Login(email, password string) (string, string, error)
	RefreshToken(refreshToken string) (string, string, error)
	ValidateAccessToken(token string) (string, error)
	ValidateRefreshToken(token string) (string, error)
}

type Handler struct {
	svc Service
}

func NewHandler(svc Service) *Handler {
	return &Handler{svc}
}

func (handler *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := handler.svc.Register(req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (handler *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := handler.svc.Login(req.Email, req.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (handler *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := handler.svc.RefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (handler *Handler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	token = token[7:]
	email, err := handler.svc.ValidateAccessToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(models.ValidateResponse{
		Email: email,
	})
}
