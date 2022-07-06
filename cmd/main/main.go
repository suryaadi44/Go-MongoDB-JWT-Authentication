package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/suryaadi44/Go-MongoDB-JWT-Authentication/pkg/controller"
	"github.com/suryaadi44/Go-MongoDB-JWT-Authentication/pkg/database"
	"go.mongodb.org/mongo-driver/mongo"
)

func init() {
	_, present := os.LookupEnv("APP_NAME")
	if !present {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("[ENV] Error loading .env file")
		}
	}

	log.Printf("[APP] %s started\n", os.Getenv("APP_NAME"))
}

func InitializeDatabase() *mongo.Database {
	return database.ConnectDatabase(
		os.Getenv("DB_URI"),
		os.Getenv("DB_NAME"),
	)
}

func InitializeController() *fiber.App {
	appName := os.Getenv("APP_NAME")
	if appName == "" {
		appName = "Development"
	}

	return fiber.New(fiber.Config{
		Prefork:      os.Getenv("PREFORK") == "true",
		ServerHeader: appName,
	})
}

func main() {
	db := InitializeDatabase()
	defer db.Client().Disconnect(context.Background())

	app := InitializeController()

	controller.InitializeController(app, db)

	port := fmt.Sprintf(":%s", os.Getenv("PORT"))
	err := app.Listen(port)
	if err != nil {
		log.Println("[Server] Error starting server:", err)
	}
}
