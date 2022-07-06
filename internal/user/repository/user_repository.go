package repository

import (
	"context"
	"time"

	entity "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/entitiy"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	db *mongo.Database
}

func NewUserRepository(db *mongo.Database) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (u *UserRepository) CreateUser(ctx context.Context, user entity.User) error {
	collection := u.db.Collection("users")

	_, err := collection.InsertOne(ctx, user)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserRepository) IsEmailExists(ctx context.Context, email string) bool {
	collection := u.db.Collection("users")

	var user entity.User
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return false
	}

	return true
}

func (u *UserRepository) IsUsernameExists(ctx context.Context, username string) bool {
	collection := u.db.Collection("users")

	var user entity.User
	err := collection.FindOne(ctx, bson.M{"_id": username}).Decode(&user)
	if err != nil {
		return false
	}

	return true
}

func (u *UserRepository) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	collection := u.db.Collection("users")

	var user entity.User
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return user, err
	}

	return user, nil
}

func (u *UserRepository) AddTokenToBlacklist(ctx context.Context, token string, expiresAt time.Time) error {
	collection := u.db.Collection("blacklisted_tokens")

	_, err := collection.InsertOne(ctx, entity.BlackListedToken{
		Token:     token,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	return nil
}
