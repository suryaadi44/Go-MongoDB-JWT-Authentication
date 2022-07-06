package controller

import (
	"github.com/gofiber/fiber/v2"
	"github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/dto"
	"github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/service"

	global "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/pkg/dto"
)

type UserController struct {
	Router      fiber.Router
	UserService service.UserService
}

func NewUserController(Router fiber.Router, userService service.UserService) *UserController {
	return &UserController{
		Router:      Router,
		UserService: userService,
	}
}

func (u *UserController) InitializeController() {
	u.Router.Post("/user/signup", u.RegisterUser)
	u.Router.Post("/user/login", u.AuthenticateUser)
	u.Router.Get("/user/logout", u.LogOutUser)
}

func (u *UserController) RegisterUser(c *fiber.Ctx) error {
	var user dto.RegisterRequest
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(global.NewBaseResponse(fiber.StatusInternalServerError, err.Error()))
	}

	if exists := u.UserService.IsEmailExists(c.Context(), user.Email); exists {
		return c.Status(fiber.StatusBadRequest).JSON(global.NewBaseResponse(fiber.StatusBadRequest, "Email already registered"))
	}

	if exists := u.UserService.IsUsernameExists(c.Context(), user.Username); exists {
		return c.Status(fiber.StatusBadRequest).JSON(global.NewBaseResponse(fiber.StatusBadRequest, "Username already registered"))
	}

	err := u.UserService.CreateUser(c.Context(), user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(global.NewBaseResponse(fiber.StatusInternalServerError, err.Error()))
	}
	return c.Status(fiber.StatusCreated).JSON(global.NewBaseResponse(fiber.StatusCreated, "User created successfully"))
}

func (u *UserController) AuthenticateUser(c *fiber.Ctx) error {
	var user dto.LoginRequest
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(global.NewBaseResponse(fiber.StatusInternalServerError, err.Error()))
	}

	token, err := u.UserService.AuthenticateUser(c.Context(), user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(global.NewBaseResponse(fiber.StatusInternalServerError, err.Error()))
	}

	if token == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(global.NewBaseResponse(fiber.StatusUnauthorized, "Invalid credentials"))
	}

	return c.Status(fiber.StatusOK).JSON(global.NewBaseResponse(fiber.StatusOK, *token))
}

func (u *UserController) LogOutUser(c *fiber.Ctx) error {
	// Get token from header
	token := c.Get("Authorization")

	//Strip Bearer from token
	token = token[7:]

	// Add to blacklist
	err := u.UserService.AddTokenToBlacklist(c.Context(), token)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(global.NewBaseResponse(fiber.StatusInternalServerError, err.Error()))
	}

	return c.Status(fiber.StatusOK).JSON(global.NewBaseResponse(fiber.StatusOK, "User logged out successfully"))
}
