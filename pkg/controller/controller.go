package controller

import (
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	userControllerPkg "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/controller"
	userRepositoryPkg "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/repository"
	userServicePkg "github.com/suryaadi44/Go-MongoDB-JWT-Authentication/internal/user/service"
)

func InitializeController(app *fiber.App, db *mongo.Database) {
	app.Use(cors.New())
	app.Use(favicon.New())
	app.Use(logger.New(logger.Config{
		Format:     "${time} [API] ${ip}:${port} ${status} - ${latency} ${method} ${path}\n",
		TimeFormat: "2006/01/02 15:04:05",
	}))
	app.Use(recover.New())

	api := app.Group("/api")

	userRepository := userRepositoryPkg.NewUserRepository(db)

	userService := userServicePkg.NewUserService(*userRepository)

	userController := userControllerPkg.NewUserController(api, *userService)

	userController.InitializeController()
}
