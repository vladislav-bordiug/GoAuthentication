package services

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"strings"
	"testing"
	"time"
)

type MockDatabase struct {
	mock.Mock
}

func NewMockDatabase() *MockDatabase {
	return &MockDatabase{}
}

func (m *MockDatabase) CreateTableQuery(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockDatabase) InsertTokenQuery(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockDatabase) UpdateTokenQuery(ctx context.Context, id int, refreshtoken string) error {
	args := m.Called(ctx, id, refreshtoken)
	return args.Error(0)
}

func (m *MockDatabase) SetStatusTokenQuery(ctx context.Context, id int, status string) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockDatabase) SelectRefreshTokenQuery(ctx context.Context, id int) (string, string, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(string), args.Get(1).(string), args.Error(2)
}

func TestGeneratetokens(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	database.On("InsertTokenQuery", context.Background()).
		Return(1, nil).
		Once()
	database.On("UpdateTokenQuery", context.Background(), 1, mock.AnythingOfType("string")).
		Return(nil).
		Once()
	access, refresh, err := service.Generatetokens(1, "127.0.0.1", "example@example.com")
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, access, "Access token should not be empty")
	assert.NotEmpty(t, refresh, "Refresh token should not be empty")
	assert.IsType(t, "string", access, "Access token should be a string")
	assert.IsType(t, "string", refresh, "Refresh token should be a string")
	database.AssertExpectations(t)
}

func TestGeneratetokens_DatabaseErrorInsert(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	database.On("InsertTokenQuery", context.Background()).
		Return(1, errors.New("database error insert")).
		Once()
	_, _, err := service.Generatetokens(1, "127.0.0.1", "example@example.com")
	assert.Equal(t, "database error insert", err.Error())
	database.AssertExpectations(t)
}

func TestGeneratetokens_DatabaseErrorUpdate(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	database.On("InsertTokenQuery", context.Background()).
		Return(1, nil).
		Once()
	database.On("UpdateTokenQuery", context.Background(), 1, mock.AnythingOfType("string")).
		Return(errors.New("database error update")).
		Once()
	_, _, err := service.Generatetokens(1, "127.0.0.1", "example@example.com")
	assert.Equal(t, "database error update", err.Error())
	database.AssertExpectations(t)
}

func TestRefresh(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(refresh, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid token format")
	}
	sign := parts[2]
	dbrefresh, err := makebcrypt(sign)
	if err != nil {
		t.Fatal(err)
	}
	database.On("SelectRefreshTokenQuery", context.Background(), 1).
		Return(dbrefresh, "unused", nil).
		Once()
	database.On("InsertTokenQuery", context.Background()).
		Return(1, nil).
		Once()
	database.On("UpdateTokenQuery", context.Background(), 1, mock.AnythingOfType("string")).
		Return(nil).
		Once()
	database.On("SetStatusTokenQuery", context.Background(), 1, "used").
		Return(nil).
		Once()
	access, refresh, err, status := service.Refresh(refresh, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, access, "Access token should not be empty")
	assert.NotEmpty(t, refresh, "Refresh token should not be empty")
	assert.IsType(t, "string", access, "Access token should be a string")
	assert.IsType(t, "string", refresh, "Refresh token should be a string")
	database.AssertExpectations(t)
}

func TestRefresh_InvalidJWTError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	refresh := "invalidjwt"
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Invalid JWT Token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)

}

func TestRefresh_InvalidIDError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    "id",
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Invalid id in token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestRefresh_InvalidTypeError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  123,
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Invalid type in token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestRefresh_InvalidIPError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    1234,
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Invalid ip in token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestRefresh_InvalidGUIDError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  "guid",
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Invalid guid in token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestRefresh_InvalidEmailError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": 123,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Invalid email in token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestRefresh_InvalidTokenTypeError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "access",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "This is not a refresh token", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestRefresh_UsedTokenError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(refresh, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid token format")
	}
	sign := parts[2]
	dbrefresh, err := makebcrypt(sign)
	if err != nil {
		t.Fatal(err)
	}
	database.On("SelectRefreshTokenQuery", context.Background(), 1).
		Return(dbrefresh, "used", nil).
		Once()
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Refresh token was used or blocked", err.Error())
	assert.Equal(t, http.StatusBadRequest, status)
	database.AssertExpectations(t)
}

func TestRefresh_DatabaseSelectError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(refresh, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid token format")
	}
	sign := parts[2]
	dbrefresh, err := makebcrypt(sign)
	if err != nil {
		t.Fatal(err)
	}
	database.On("SelectRefreshTokenQuery", context.Background(), 1).
		Return(dbrefresh, "unused", errors.New("Error selecting status and refresh hash from database")).
		Once()
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Error selecting status and refresh hash from database", err.Error())
	assert.Equal(t, http.StatusInternalServerError, status)
	database.AssertExpectations(t)
}

func TestRefresh_DatabaseSetStatusError(t *testing.T) {
	database := NewMockDatabase()
	service := NewService(database, "secret", "user", "pass", "from@example.com")
	payload := jwt.MapClaims{
		"guid":  1,
		"email": "example@example.com",
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"ip":    "127.0.0.1",
		"type":  "refresh",
		"id":    1,
	}
	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	refresh, err := refreshtoken.SignedString([]byte(service.secret))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(refresh, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid token format")
	}
	sign := parts[2]
	dbrefresh, err := makebcrypt(sign)
	if err != nil {
		t.Fatal(err)
	}
	database.On("SelectRefreshTokenQuery", context.Background(), 1).
		Return(dbrefresh, "unused", nil).
		Once()
	database.On("InsertTokenQuery", context.Background()).
		Return(1, nil).
		Once()
	database.On("UpdateTokenQuery", context.Background(), 1, mock.AnythingOfType("string")).
		Return(nil).
		Once()
	database.On("SetStatusTokenQuery", context.Background(), 1, "used").
		Return(errors.New("Error setting status in database")).
		Once()
	_, _, err, status := service.Refresh(refresh, "127.0.0.1")
	assert.Equal(t, "Error setting status in database", err.Error())
	assert.Equal(t, http.StatusInternalServerError, status)
	database.AssertExpectations(t)
}
