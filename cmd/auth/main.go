package main

import (
	"context"
	"log"
	"net/http"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/awslabs/aws-lambda-go-api-proxy/gorillamux"
	"github.com/gorilla/mux"

	appConfig "auth-service/internal/config"
	"auth-service/internal/core"
	"auth-service/internal/database"
	"auth-service/internal/middleware"
)

var muxLambda *gorillamux.GorillaMuxAdapter

func init() {
	cfg := appConfig.Load()

	awsCfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load AWS SDK config: %v", err)
	}

	db := database.New(
		dynamodb.NewFromConfig(awsCfg),
		cfg.UsersTable,
		cfg.TokensTable,
	)

	svc := core.NewService(db, cfg.JWTSecret, cfg.RefreshSecret)
	handler := core.NewHandler(svc)

	router := mux.NewRouter()
	router.Use(middleware.CORSMiddleware)

	router.PathPrefix("/").Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	auth := router.PathPrefix("/auth").Subrouter()

	// Public routes
	auth.HandleFunc("/register", handler.Register).Methods("POST")
	auth.HandleFunc("/login", handler.Login).Methods("POST")
	auth.HandleFunc("/refresh", handler.Refresh).Methods("POST")
	auth.HandleFunc("/logout", handler.Logout).Methods("POST")

	// Protected routes
	protected := auth.PathPrefix("").Subrouter()
	protected.Use(middleware.AuthMiddleware([]byte(cfg.JWTSecret)))
	protected.HandleFunc("/me", handler.Me).Methods("GET")
	protected.HandleFunc("/delete", handler.DeleteAccount).Methods("DELETE")
	protected.HandleFunc("/updateName", handler.UpdateUser).Methods("PATCH")

	// Admin only route
	admin := router.PathPrefix("/admin").Subrouter()
	admin.Use(middleware.AuthMiddleware([]byte(cfg.JWTSecret)))
	admin.HandleFunc("/users", handler.GetAllUsers).Methods("GET")

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			next.ServeHTTP(w, r)
		})
	})

	muxLambda = gorillamux.New(router)
}

func main() {
	lambda.Start(muxLambda.ProxyWithContext)
}
