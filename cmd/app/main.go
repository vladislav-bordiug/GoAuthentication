package main

import (
	"GoAuthentication/internal/app"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"os"
)

// @title Go Authentication JWT
// @version 1.0
// @description This is a sample server for getting and refreshing access and refresh JWT tokens

// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
//
// @securityDefinitions.apikey  X-Refresh-Token
// @in                          header
// @name                        X-Refresh-Token
func main() {
	dbHost := os.Getenv("DATABASE_HOST")
	dbPort := os.Getenv("DATABASE_PORT")
	dbUser := os.Getenv("DATABASE_USER")
	dbPassword := os.Getenv("DATABASE_PASSWORD")
	dbName := os.Getenv("DATABASE_NAME")
	jwtSecret := os.Getenv("SECRET_KEY")
	serverIP := os.Getenv("SERVER_IP")
	serverPort := os.Getenv("SERVER_PORT")
	webhookurl := os.Getenv("WEBHOOK_URL")
	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" || serverPort == "" || jwtSecret == "" || serverIP == "" || webhookurl == "" {
		log.Fatal("\nNot all environment variables are set")
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatal("Error while creating connection to the database!", err)
	}
	defer db.Close()
	application := app.NewApp(db, jwtSecret, serverIP, serverPort, webhookurl)
	log.Fatal(application.Run())
}
