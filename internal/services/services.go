package services

import (
	"GoAuthentication/internal/database"
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	gomail "gopkg.in/mail.v2"
	"net/http"
	"strings"
	"time"
)

type Service struct {
	database  database.Database
	secret    string
	mailuser  string
	mailpass  string
	fromemail string
}

func NewService(db database.Database, secret string, mailuser string, mailpass string, fromemail string) *Service {
	return &Service{database: db, secret: secret, mailuser: mailuser, mailpass: mailpass, fromemail: fromemail}
}

func (s *Service) Generatetokens(guid int, ipaddress string, email string) (accessToken string, refreshToken string, err error) {
	id, err := s.database.InsertTokenQuery(context.Background())
	if err != nil {
		return "", "", err
	}
	payloadaccess := jwt.MapClaims{
		"guid":  guid,
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    ipaddress,
		"type":  "access",
		"id":    id,
	}
	accesstoken := jwt.NewWithClaims(jwt.SigningMethodHS512, payloadaccess)
	access, err := accesstoken.SignedString([]byte(s.secret))
	if err != nil {
		return "", "", err
	}
	payloadrefresh := jwt.MapClaims{
		"guid":  guid,
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24 * 10).Unix(),
		"ip":    ipaddress,
		"type":  "refresh",
		"id":    id,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payloadrefresh)
	refresh, err := refreshtoken.SignedString([]byte(s.secret))
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(refresh, ".")
	if len(parts) != 3 {
		return "", "", errors.New("Invalid token format")
	}
	sign := parts[2]
	sign, err = makebcrypt(sign)
	if err != nil {
		return "", "", err
	}
	if err = s.database.UpdateTokenQuery(context.Background(), id, sign); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (s *Service) extractClaims(tokenStr string) (jwt.MapClaims, bool) {
	hmacSecretString := s.secret
	hmacSecret := []byte(hmacSecretString)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return hmacSecret, nil
	})
	if err != nil {
		return nil, false
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	} else {
		return nil, false
	}
}

func makebcrypt(fresh string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(fresh), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkbcrypt(receivedrefresh string, databaserefresh string) error {
	password := []byte(receivedrefresh)
	hashedPassword := []byte(databaserefresh)
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)
	return err
}

func (s *Service) Refresh(currentrefresh string, ipaddress string) (string, string, error, int) {
	claims, ok := s.extractClaims(currentrefresh)
	if !ok {
		return "", "", errors.New("Invalid JWT Token"), http.StatusBadRequest
	}
	d, ok := claims["id"].(float64)
	if !ok {
		return "", "", errors.New("Invalid id in token"), http.StatusBadRequest
	}
	id := int(d)
	typee, ok := claims["type"].(string)
	if !ok {
		return "", "", errors.New("Invalid type in token"), http.StatusBadRequest
	}
	ip, ok := claims["ip"].(string)
	if !ok {
		return "", "", errors.New("Invalid ip in token"), http.StatusBadRequest
	}
	gid, ok := claims["guid"].(float64)
	if !ok {
		return "", "", errors.New("Invalid guid in token"), http.StatusBadRequest
	}
	guid := int(gid)
	email, ok := claims["email"].(string)
	if !ok {
		return "", "", errors.New("Invalid email in token"), http.StatusBadRequest
	}
	if typee != "refresh" {
		return "", "", errors.New("This is not a refresh token"), http.StatusBadRequest
	}
	dbrefresh, status, err := s.database.SelectRefreshTokenQuery(context.Background(), id)
	if err != nil {
		return "", "", err, http.StatusInternalServerError
	}
	if status != "unused" {
		return "", "", errors.New("Refresh token was used or blocked"), http.StatusBadRequest
	}
	parts := strings.Split(currentrefresh, ".")
	if len(parts) != 3 {
		return "", "", errors.New("Invalid token format"), http.StatusBadRequest
	}
	refresh := parts[2]
	if err = checkbcrypt(refresh, dbrefresh); err != nil {
		return "", "", err, http.StatusBadRequest
	}
	if ipaddress != ip {
		message := gomail.NewMessage()
		message.SetHeader("From", s.fromemail)
		message.SetHeader("To", email)
		message.SetHeader("Subject", "IP address has changed")
		message.SetBody("text/plain", "Your IP address has changed")
		dialer := gomail.NewDialer("sandbox.smtp.mailtrap.io", 2525, s.mailuser, s.mailpass)
		_ = dialer.DialAndSend(message)
	}
	access, refresh, err := s.Generatetokens(guid, ipaddress, email)
	if err != nil {
		return "", "", err, http.StatusInternalServerError
	}
	if err = s.database.SetStatusTokenQuery(context.Background(), id, "used"); err != nil {
		return "", "", err, http.StatusInternalServerError
	}
	return access, refresh, nil, 200
}
