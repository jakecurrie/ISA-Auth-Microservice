package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"auth-service/internal/models"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user already exists")
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
	log.Printf("Creating user with ID: %s in table: %s", user.ID, db.usersTable)

	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		log.Printf("Error marshaling user: %v", err)
		return fmt.Errorf("marshal error: %w", err)
	}

	_, err = db.client.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName:           &db.usersTable,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(email)"),
	})
	if err != nil {
		log.Printf("DynamoDB PutItem error: %v", err)
		return fmt.Errorf("put item error: %w", err)
	}

	log.Printf("Successfully created user in database")
	return nil
}

func (db *DB) GetUserByEmail(email string) (*models.User, error) {
	log.Printf("Getting user by email: %s", email)
	log.Printf("Using table: %s", db.usersTable)

	result, err := db.client.Query(context.TODO(), &dynamodb.QueryInput{
		TableName:              &db.usersTable,
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":email": &types.AttributeValueMemberS{Value: email},
		},
	})
	if err != nil {
		log.Printf("DynamoDB Query error: %v", err)
		return nil, fmt.Errorf("query error: %w", err)
	}

	log.Printf("Query result items length: %d", len(result.Items))
	if len(result.Items) == 0 {
		return nil, nil
	}

	var user models.User
	err = attributevalue.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return &user, nil
}

func (db *DB) GetUserByID(id string) (*models.User, error) {
	result, err := db.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: &db.usersTable,
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})

	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, ErrUserNotFound
	}

	var user models.User
	err = attributevalue.UnmarshalMap(result.Item, &user)
	return &user, err
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

func (db *DB) ValidateRefreshToken(userID, token string) (bool, error) {
	result, err := db.client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: &db.tokensTable,
		Key: map[string]types.AttributeValue{
			"user_id": &types.AttributeValueMemberS{Value: userID},
		},
	})

	if err != nil {
		return false, err
	}

	if result.Item == nil {
		return false, nil
	}

	var storedToken models.RefreshToken
	if err := attributevalue.UnmarshalMap(result.Item, &storedToken); err != nil {
		return false, err
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return false, nil
	}

	return storedToken.Token == token, nil
}

func (db *DB) UpdateLastActive(userID string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: &db.usersTable,
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: userID},
		},
		UpdateExpression: aws.String("SET last_active = :time"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":time": &types.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339)},
		},
	}

	_, err := db.client.UpdateItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error updating last active field in dynamodb")
		return fmt.Errorf("DB update error: %w", err)
	}
	return err
}

func (db *DB) GetAllUsers() ([]models.User, error) {
	input := &dynamodb.ScanInput{
		TableName: &db.usersTable,
	}

	result, err := db.client.Scan(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to scan users: %w", err)
	}

	users := make([]models.User, 0)
	for _, item := range result.Items {
		var user models.User
		if err := attributevalue.UnmarshalMap(item, &user); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user: %w", err)
		}
		user.Password = ""
		users = append(users, user)
	}

	return users, nil
}
