package main

import (
	"GoAuthentication/internal/app"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"os"
	"time"
)

func Config() *pgxpool.Config {
	// const defaultMaxConns = int32(4)
	// const defaultMinConns = int32(0)
	const defaultMaxConnLifetime = time.Hour
	const defaultMaxConnIdleTime = time.Minute * 30
	const defaultHealthCheckPeriod = time.Minute
	const defaultConnectTimeout = time.Second * 5
	dbConfig, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Failed to create a config, error: ", err)
	}
	// dbConfig.MaxConns = defaultMaxConns
	// dbConfig.MinConns = defaultMinConns
	dbConfig.MaxConnLifetime = defaultMaxConnLifetime
	dbConfig.MaxConnIdleTime = defaultMaxConnIdleTime
	dbConfig.HealthCheckPeriod = defaultHealthCheckPeriod
	dbConfig.ConnConfig.ConnectTimeout = defaultConnectTimeout
	return dbConfig
}

// @title Go Authentication JWT
// @version 1.0
// @description This is a sample server for getting and refreshing access and refresh JWT tokens

// @securityDefinitions.apikey X-Refresh-Token
// @in header
// @name X-Refresh-Token

func main() {
	connPool, err := pgxpool.NewWithConfig(context.Background(), Config())
	if err != nil {
		log.Fatal("Error while creating connection to the database!", err)
	}
	defer connPool.Close()
	connection, err := connPool.Acquire(context.Background())
	if err != nil {
		log.Fatal("Error while acquiring connection from the database pool!", err)
	}
	defer connection.Release()
	err = connection.Ping(context.Background())
	if err != nil {
		log.Fatal("Could not ping database", err)
	}
	application := app.NewApp(connPool, os.Getenv("SECRET_KEY"), os.Getenv("SERVER_IP"), os.Getenv("SERVER_PORT"), os.Getenv("MAILTRAP_USERNAME"), os.Getenv("MAILTRAP_PASSWORD"), os.Getenv("FROM_EMAIL"))
	log.Fatal(application.Run())
}
