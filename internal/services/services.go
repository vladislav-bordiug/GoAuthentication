package services

import (
	"GoAuthentication/internal/database"
	"GoAuthentication/internal/models"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

type ServiceInterface interface {
	GenerateTokens(guid int, ip, ua string) (accessJWT, refreshBase64 string, err error)
	RefreshTokens(accessBearer, refreshB64, ip, ua string) (newAccess, newRefresh string, status int, err error)
	Logout(guid int) error
	ValidateAccess(accessBearer string) (guid int, err error)
}

type Service struct {
	db         database.Database
	secret     string
	webhookURL string
}

func NewService(db database.Database, secret string, webhookURL string) *Service {
	return &Service{db: db, secret: secret, webhookURL: webhookURL}
}

func (s *Service) ValidateAccess(accessBearer string) (int, error) {
	parts := strings.SplitN(accessBearer, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return 0, errors.New("Invalid Authorization header")
	}
	tokenStr := parts[1]

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS512 {
			return nil, errors.New("Unexpected signing method")
		}
		return []byte(s.secret), nil
	})
	if err != nil || !token.Valid {
		return 0, errors.New("Invalid access token")
	}
	claims := token.Claims.(jwt.MapClaims)

	if claims["type"] != "access" {
		return 0, errors.New("Not an access token")
	}

	idFloat, _ := claims["id"].(float64)
	id := int(idFloat)
	_, status, err := s.db.GetRefresh(context.Background(), id)
	if err != nil {
		return 0, err
	}
	if status == "blocked" {
		return 0, errors.New("Token revoked")
	}

	guidFloat, _ := claims["guid"].(float64)
	return int(guidFloat), nil
}

func (s *Service) GenerateTokens(guid int, ip, ua string) (accessJWT, refreshBase64 string, err error) {
	id, err := s.db.InsertToken(context.Background(), guid)
	if err != nil {
		return "", "", err
	}

	claims := jwt.MapClaims{
		"guid": guid,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
		"ip":   ip,
		"ua":   ua,
		"id":   id,
		"type": "access",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessJWT, err = token.SignedString([]byte(s.secret))
	if err != nil {
		return "", "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	refreshBase64 = base64.StdEncoding.EncodeToString(raw)

	hash, err := bcrypt.GenerateFromPassword(raw, bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	if err := s.db.StoreRefresh(context.Background(), id, string(hash)); err != nil {
		return "", "", err
	}

	return accessJWT, refreshBase64, nil
}

func (s *Service) RefreshTokens(accessBearer, refreshB64, ip, ua string) (newAccess, newRefresh string, status int, err error) {
	parts := strings.SplitN(accessBearer, " ", 2)
	if len(parts) != 2 {
		return "", "", http.StatusBadRequest, errors.New("Invalid Authorization header")
	}
	tokenStr := parts[1]
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS512 {
			return nil, errors.New("Unexpected signing method")
		}
		return []byte(s.secret), nil
	})
	if err != nil || !token.Valid {
		return "", "", http.StatusUnauthorized, errors.New("Invalid access token")
	}
	claims := token.Claims.(jwt.MapClaims)

	if claims["type"] != "access" {
		return "", "", http.StatusBadRequest, errors.New("Not an access token")
	}
	id := int(claims["id"].(float64))
	origUA := claims["ua"].(string)
	origIP := claims["ip"].(string)
	guid := int(claims["guid"].(float64))

	if ua != origUA {
		s.db.InvalidateAllRefreshForGUID(context.Background(), guid)
		return "", "", http.StatusUnauthorized, errors.New("User-Agent mismatch — you have been logged out")
	}

	storedHash, statusDB, err := s.db.GetRefresh(context.Background(), id)
	if err != nil {
		return "", "", http.StatusInternalServerError, err
	}
	if statusDB != "unused" {
		return "", "", http.StatusBadRequest, errors.New("Refresh token already used or blocked")
	}

	raw, err := base64.StdEncoding.DecodeString(refreshB64)
	if err != nil {
		return "", "", http.StatusBadRequest, errors.New("Invalid base64")
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), raw) != nil {
		return "", "", http.StatusUnauthorized, errors.New("Invalid refresh token")
	}

	if ip != origIP {
		go func() {
			payload := models.IPChangeRequest{
				GUID:     guid,
				FromIP:   origIP,
				NewIP:    ip,
				DateTime: time.Now().UTC(),
			}
			b, _ := json.Marshal(payload)
			http.Post(s.webhookURL, "application/json", bytes.NewReader(b))
		}()
	}

	s.db.MarkRefreshUsed(context.Background(), id)

	access, refresh, genErr := s.GenerateTokens(guid, ip, ua)
	if genErr != nil {
		return "", "", http.StatusInternalServerError, genErr
	}

	return access, refresh, http.StatusOK, nil
}

func (s *Service) Logout(guid int) error {
	return s.db.InvalidateAllRefreshForGUID(context.Background(), guid)
}
