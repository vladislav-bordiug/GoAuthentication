package rest

import (
	"GoAuthentication/internal/models"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type MockInterface struct {
	mock.Mock
}

func NewMockInterface() *MockInterface {
	return &MockInterface{}
}

func (m *MockInterface) Generatetokens(guid int, ipaddress string, email string) (string, string, error) {
	args := m.Called(guid, ipaddress, email)
	return args.Get(0).(string), args.Get(1).(string), args.Error(2)
}

func (m *MockInterface) Refresh(currentrefresh string, ipaddress string) (string, string, error, int) {
	args := m.Called(currentrefresh, ipaddress)
	return args.Get(0).(string), args.Get(1).(string), args.Error(2), args.Get(3).(int)
}

func TestCreateTokens(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	requestData := models.Request{
		GUID:  1,
		EMail: "example@example.com",
	}
	requestBody, _ := json.Marshal(requestData)
	mockinterface.On("Generatetokens", requestData.GUID, "127.0.0.1", requestData.EMail).
		Return("token1", "token2", nil).
		Once()
	req, err := http.NewRequest("POST", "/create", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rr := httptest.NewRecorder()
	handler.CreateTokens(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	mockinterface.AssertExpectations(t)
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("error reading body")
}

func TestCreateTokens_ReadBodyError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	req, err := http.NewRequest("POST", "/create", io.NopCloser(errReader(0)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rr := httptest.NewRecorder()
	handler.CreateTokens(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "error reading body")
}

func TestCreateTokens_UnmarshalError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	invalidJSON := `{"guid": 1, "email":`
	req, err := http.NewRequest("POST", "/create", bytes.NewReader([]byte(invalidJSON)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rr := httptest.NewRecorder()
	handler.CreateTokens(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unexpected end of JSON input")
}

func TestCreateTokens_IPAddressError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	requestData := models.Request{
		GUID:  1,
		EMail: "example@example.com",
	}
	requestBody, _ := json.Marshal(requestData)
	req, err := http.NewRequest("POST", "/create", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1"
	rr := httptest.NewRecorder()
	handler.CreateTokens(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing port in address")
}

func TestCreateTokens_GeneratetokensError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	requestData := models.Request{
		GUID:  1,
		EMail: "example@example.com",
	}
	requestBody, _ := json.Marshal(requestData)
	mockinterface.On("Generatetokens", requestData.GUID, "127.0.0.1", requestData.EMail).
		Return("token1", "token2", errors.New("error generating tokens")).
		Once()
	req, err := http.NewRequest("POST", "/create", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rr := httptest.NewRecorder()
	handler.CreateTokens(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockinterface.AssertExpectations(t)
	assert.Contains(t, rr.Body.String(), "error generating tokens")
}

type errorWriter struct {
	*httptest.ResponseRecorder
}

func (ew *errorWriter) Write(data []byte) (int, error) {
	ew.Body.Write([]byte("forced encoding error"))
	return 0, fmt.Errorf("forced encoding error")
}

func TestCreateTokens_NewEncoderEncodeError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	requestData := models.Request{
		GUID:  1,
		EMail: "example@example.com",
	}
	requestBody, _ := json.Marshal(requestData)
	mockinterface.On("Generatetokens", requestData.GUID, "127.0.0.1", requestData.EMail).
		Return("token1", "token2", nil).
		Once()
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/create", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	handler.CreateTokens(&errorWriter{ResponseRecorder: rr}, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockinterface.AssertExpectations(t)
	assert.Contains(t, rr.Body.String(), "forced encoding error")
}

func TestRefreshTokens(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	mockinterface.On("Refresh", "refresh", "127.0.0.1").
		Return("token1", "token2", nil, 200).
		Once()
	req, err := http.NewRequest("GET", "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Refresh-Token", "refresh")
	rr := httptest.NewRecorder()
	handler.RefreshTokens(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	mockinterface.AssertExpectations(t)
}

func TestRefreshTokens_IPAddressError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	req, err := http.NewRequest("GET", "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1"
	rr := httptest.NewRecorder()
	handler.RefreshTokens(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing port in address")
}

func TestRefreshTokens_RefreshError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	mockinterface.On("Refresh", "refresh", "127.0.0.1").
		Return("token1", "token2", errors.New("refresh error"), 500).
		Once()
	req, err := http.NewRequest("GET", "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Refresh-Token", "refresh")
	rr := httptest.NewRecorder()
	handler.RefreshTokens(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockinterface.AssertExpectations(t)
	assert.Contains(t, rr.Body.String(), "refresh error")
}

func TestRefreshTokens_NewEncoderEncodeError(t *testing.T) {
	mockinterface := NewMockInterface()
	handler := &Handler{
		mockinterface,
	}
	mockinterface.On("Refresh", "refresh", "127.0.0.1").
		Return("token1", "token2", nil, 200).
		Once()
	req, err := http.NewRequest("GET", "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Refresh-Token", "refresh")
	handler.RefreshTokens(&errorWriter{ResponseRecorder: rr}, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockinterface.AssertExpectations(t)
	assert.Contains(t, rr.Body.String(), "forced encoding error")
}
