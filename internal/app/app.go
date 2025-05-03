package app

import (
	_ "GoAuthentication/docs"
	"GoAuthentication/internal/database"
	"GoAuthentication/internal/services"
	"GoAuthentication/internal/transport/rest"
	httpSwagger "github.com/swaggo/http-swagger"
	"net/http"
)

type App struct {
	pool       database.DBPool
	secret     string
	ip         string
	port       string
	webhookurl string
}

func NewApp(pool database.DBPool, secret string, ip string, port string, webhookurl string) *App {
	return &App{pool: pool, secret: secret, ip: ip, port: port, webhookurl: webhookurl}
}

func (a *App) Run() error {
	db := database.NewPGXDatabase(a.pool)
	tokenservice := services.NewService(db, a.secret, a.webhookurl)
	handler := rest.NewHandler(tokenservice)
	http.HandleFunc("/create", handler.CreateTokens)
	http.HandleFunc("/refresh", handler.RefreshTokens)
	http.HandleFunc("/me", handler.GetCurrentUser)
	http.HandleFunc("/logout", handler.Logout)
	http.Handle("/swagger/", httpSwagger.WrapHandler)
	err := http.ListenAndServe(a.ip+":"+a.port, nil)
	return err
}
