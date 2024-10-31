package database

import (
	"context"
	"time"

	"auth-service/internal/models"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DB struct {
	client      *dynamodb.Client
	usersTable  string
	tokensTable string
}

func New(client *dynamodb.Client, usersTable, tokensTable string) *DB {
	return &DB{
		client:      client,
		usersTable:  usersTable,
		tokensTable: tokensTable,
	}
}

func (db *DB) CreateUser(user *models.User) error {
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return err
	}

	_, err = db.client.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: &db.usersTable,
		Item:      item,
	})
	return err
}

func (db *DB) GetUser(email string) (*models.User, error) {
	out, err := db.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: &db.usersTable,
		Key: map[string]types.AttributeValue{
			"email": &types.AttributeValueMemberS{Value: email},
		},
	})
	if err != nil {
		return nil, err
	}

	if out.Item == nil {
		return nil, nil
	}

	var user models.User
	if err := attributevalue.UnmarshalMap(out.Item, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *DB) StoreRefreshToken(token *models.RefreshToken) error {
	item, err := attributevalue.MarshalMap(token)
	if err != nil {
		return err
	}

	_, err = db.client.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: &db.tokensTable,
		Item:      item,
	})
	return err
}

func (db *DB) GetRefreshToken(email string) (*models.RefreshToken, error) {
	out, err := db.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: &db.tokensTable,
		Key: map[string]types.AttributeValue{
			"email": &types.AttributeValueMemberS{Value: email},
		},
	})
	if err != nil {
		return nil, err
	}

	if out.Item == nil {
		return nil, nil
	}

	var token models.RefreshToken
	if err := attributevalue.UnmarshalMap(out.Item, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (db *DB) ValidateRefreshToken(email, token string) (bool, error) {
	storedToken, err := db.GetRefreshToken(email)
	if err != nil {
		return false, err
	}
	if storedToken == nil {
		return false, nil
	}

	return storedToken.Token == token && time.Now().Before(storedToken.ExpiresAt), nil
}
