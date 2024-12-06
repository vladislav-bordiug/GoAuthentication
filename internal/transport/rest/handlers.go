package rest

import (
	"GoAuthentication/internal/models"
	"encoding/json"
	"io"
	"net"
	"net/http"
)

type ServiceInterface interface {
	Generatetokens(guid int, ipaddress string, email string) (string, string, error)
	Refresh(currentrefresh string, ipaddress string) (string, string, error, int)
}

type Handler struct {
	service ServiceInterface
}

func NewHandler(service ServiceInterface) *Handler {
	return &Handler{service: service}
}

// CreateTokens godoc
// @Summary Create tokens
// @Description Create access and refresh tokens by user's GUID and E-Mail
// @Tags tokens
// @Accept json
// @Produce  json
// @Content-Type application/json
// @Param data body models.Request true "JSON with GUID and E-Mail"
// @Success 200 {object} models.Response "OK"
// @Failure 400 {object} string "Bad Request"
// @Failure 500 {object} string "Internal Server Error"
// @Router /create [post]
func (h *Handler) CreateTokens(w http.ResponseWriter, r *http.Request) {
	var reqdata models.Request
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
	if IPAddress == "" {
		IPAddress, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	access, refresh, err := h.service.Generatetokens(reqdata.GUID, IPAddress, reqdata.EMail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var answer models.Response
	answer.AccessToken = access
	answer.RefreshToken = refresh
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(answer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// RefreshTokens godoc
// @Summary Refresh tokens
// @Description Refresh access and refresh tokens by refresh token
// @Tags tokens
// @Produce  json
// @Security X-Refresh-Token
// @Success 200 {object} models.Response "OK"
// @Failure 400 {object} string "Bad Request"
// @Failure 500 {object} string "Internal Server Error"
// @Router /refresh [get]
func (h *Handler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	currentrefresh := r.Header.Get("X-Refresh-Token")
	var err error
	IPAddress := r.Header.Get("X-Forwarded-For")
	if IPAddress == "" {
		IPAddress, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	access, refresh, err, status := h.service.Refresh(currentrefresh, IPAddress)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	var answer models.Response
	answer.AccessToken = access
	answer.RefreshToken = refresh
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(answer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
