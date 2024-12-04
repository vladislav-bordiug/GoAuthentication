package GoAuthentication

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type request struct {
	GUID string `json:"guid"`
}

type response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Database interface {
	CreateTableQuery(ctx context.Context) error
	InsertTokenQuery(ctx context.Context) (int, error)
	UpdateTokenQuery(ctx context.Context, id int, refreshtoken string) error
	SetStatusTokenQuery(ctx context.Context, id int, status string) error
	SelectRefreshTokenQuery(ctx context.Context, id int) (string, string, error)
}

type Handler struct {
	Database Database
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}
	handler := &Handler{
		Database: database,
	}
	http.HandleFunc("/create", handler.createhandler)
	http.HandleFunc("/refresh", handler.refreshhandler)
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}

func (h *Handler) generatetokens(guid string, ipaddress string) (accessToken string, refreshToken string, err error) {
	id, err := h.Database.InsertTokenQuery(context.Background())
	if err != nil {
		return "", "", err
	}
	payloadaccess := jwt.MapClaims{
		"guid": guid,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
		"ip":   ipaddress,
		"type": "access",
		"id":   id,
	}
	accesstoken := jwt.NewWithClaims(jwt.SigningMethodHS512, payloadaccess)
	access, err := accesstoken.SignedString(os.Getenv("SECRET_KEY"))
	if err != nil {
		return "", "", err
	}
	payloadrefresh := jwt.MapClaims{
		"guid": guid,
		"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
		"ip":   ipaddress,
		"type": "refresh",
		"id":   id,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS512, payloadrefresh)
	refresh, err := refreshtoken.SignedString(os.Getenv("SECRET_KEY"))
	if err != nil {
		return "", "", err
	}
	refresh, err = makebcrypt(refresh)
	if err != nil {
		return "", "", err
	}
	err = h.Database.UpdateTokenQuery(context.Background(), id, refresh)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (h *Handler) createhandler(w http.ResponseWriter, r *http.Request) {
	var reqdata request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = json.Unmarshal(body, &reqdata); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	IPAddress := r.Header.Get("X-Forwarded-For")
	access, refresh, err := h.generatetokens(reqdata.GUID, IPAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var answer response
	answer.AccessToken = access
	answer.RefreshToken = refresh
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(answer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func extractClaims(tokenStr string) (jwt.MapClaims, bool) {
	hmacSecretString := os.Getenv("SECRET_KEY")
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

func (h *Handler) refreshhandler(w http.ResponseWriter, r *http.Request) {
	currentrefresh := r.Header.Get("X-Refresh-Token")
	claims, ok := extractClaims(currentrefresh)
	if ok == false {
		http.Error(w, "Invalid JWT Token", http.StatusBadRequest)
		return
	}
	id, ok := claims["id"].(int)
	if !ok {
		http.Error(w, "Invalid id in token", http.StatusBadRequest)
		return
	}
	typee, ok := claims["type"].(string)
	if !ok {
		http.Error(w, "Invalid type in token", http.StatusBadRequest)
		return
	}
	ip, ok := claims["ip"].(string)
	if !ok {
		http.Error(w, "Invalid ip in token", http.StatusBadRequest)
		return
	}
	guid, ok := claims["guid"].(string)
	if !ok {
		http.Error(w, "Invalid guid in token", http.StatusBadRequest)
		return
	}
	if typee != "refresh" {
		http.Error(w, "This is not a refresh token", http.StatusBadRequest)
		return
	}
	dbrefresh, status, err := h.Database.SelectRefreshTokenQuery(context.Background(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status != "unused" {
		http.Error(w, "Refresh token was used or blocked", http.StatusInternalServerError)
		return
	}
	err = checkbcrypt(currentrefresh, dbrefresh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	IPAddress := r.Header.Get("X-Forwarded-For")
	if IPAddress != ip {
		//send e-mail
	}
	access, refresh, err := h.generatetokens(guid, IPAddress)
	err = h.Database.SetStatusTokenQuery(context.Background(), id, "used")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var answer response
	answer.AccessToken = access
	answer.RefreshToken = refresh
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(answer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
