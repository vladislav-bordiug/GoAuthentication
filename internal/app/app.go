package app

import (
	"GoAuthentication/internal/database"
	"GoAuthentication/internal/services"
	"GoAuthentication/internal/transport/rest"
	"context"
	"net/http"
)

type App struct {
	pool      database.DBPool
	secret    string
	ip        string
	port      string
	mailuser  string
	mailpass  string
	fromemail string
}

func NewApp(pool database.DBPool, secret string, ip string, port string, mailuser string, mailpass string, fromemail string) *App {
	return &App{pool: pool, secret: secret, ip: ip, port: port, mailuser: mailuser, mailpass: mailpass, fromemail: fromemail}
}

func (a *App) Run() error {
	db := database.NewPGXDatabase(a.pool)
	err := db.CreateTableQuery(context.Background())
	if err != nil {
		return err
	}
	tokenservice := services.NewService(db, a.secret, a.mailuser, a.mailpass, a.fromemail)
	handler := rest.NewHandler(tokenservice)
	http.HandleFunc("/create", handler.CreateTokens)
	http.HandleFunc("/refresh", handler.RefreshTokens)
	err = http.ListenAndServe(a.ip+":"+a.port, nil)
	return err
}
