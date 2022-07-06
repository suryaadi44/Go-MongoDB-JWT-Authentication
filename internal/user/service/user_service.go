package service

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/dto"
	entity "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/entitiy"
	userRepositoryPkg "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/repository"
	"github.com/suryaadi44/Go-MongoDB-JWT-Authentication/pkg/utils"
)

type UserService struct {
	userRepository userRepositoryPkg.UserRepository
}

func NewUserService(repository userRepositoryPkg.UserRepository) *UserService {
	return &UserService{
		userRepository: repository,
	}
}

func (u UserService) CreateUser(ctx context.Context, user dto.RegisterRequest) error {
	hash, err := utils.HashPassword(user.Password)
	if err != nil {
		log.Println("[User] Error hashing password :", err)
		return err
	}

	userEntity := entity.User{
		Username: user.Username,
		Email:    user.Email,
		Password: hash,
		Rank:     0,
		Created:  time.Now(),
	}

	err = u.userRepository.CreateUser(ctx, userEntity)
	if err != nil {
		log.Println("[User] Error creating user :", err)
		return err
	}

	return nil
}

func (u UserService) IsEmailExists(ctx context.Context, email string) bool {
	return u.userRepository.IsEmailExists(ctx, email)
}

func (u UserService) IsUsernameExists(ctx context.Context, username string) bool {
	return u.userRepository.IsUsernameExists(ctx, username)
}

func (u UserService) AuthenticateUser(ctx context.Context, user dto.LoginRequest) (*string, error) {
	savedUser, err := u.userRepository.GetUserByEmail(ctx, user.Email)
	if err != nil {
		log.Println("[User] Error getting user :", err)
		return nil, err
	}

	if !utils.CheckPasswordHash(user.Password, savedUser.Password) {
		return nil, nil
	}

	//Create jwt claims
	claims := jwt.MapClaims{
		"username":   savedUser.Username,
		"permission": savedUser.Rank,
		"exp":        time.Now().Add(time.Hour * 2).Unix(),
	}

	//Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//Sign token
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Println("[User] Error signing token :", err)
		return nil, err
	}

	return &tokenString, nil
}

func (u UserService) AddTokenToBlacklist(ctx context.Context, tokenString string) error {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		log.Println("[User] Error parsing token :", err)
		return err
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)

	var expiresAt time.Time
	if !ok {
		expiresAt = time.Now().Add(time.Hour * 2)
	} else {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	}

	err = u.userRepository.AddTokenToBlacklist(ctx, tokenString, expiresAt)
	if err != nil {
		log.Println("[User] Error adding token to blacklist :", err)
		return err
	}

	return nil
}
