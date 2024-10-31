package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/awslabs/aws-lambda-go-api-proxy/gorillamux"
	"github.com/gorilla/mux"

	appConfig "auth-service/internal/config"
	"auth-service/internal/core"
	"auth-service/internal/database"
)

var muxLambda *gorillamux.GorillaMuxAdapter

func init() {
	cfg := appConfig.Load()
	awsCfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}

	db := database.New(
		dynamodb.NewFromConfig(awsCfg),
		cfg.UsersTable,
		cfg.TokensTable,
	)

	svc := core.NewService(db, cfg.JWTSecret, cfg.RefreshSecret)
	handler := core.NewHandler(svc)
	router := mux.NewRouter()

	router.HandleFunc("/register", handler.Register).Methods("POST")
	router.HandleFunc("/login", handler.Login).Methods("POST")
	router.HandleFunc("/refresh", handler.Refresh).Methods("POST")

	muxLambda = gorillamux.New(router)
}

func main() {
	lambda.Start(muxLambda.ProxyWithContext)
}
