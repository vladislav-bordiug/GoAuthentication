package rest

import (
	"GoAuthentication/internal/models"
	"GoAuthentication/internal/services"
	"encoding/json"
	"net"
	"net/http"
)

type Handler struct {
	service services.ServiceInterface
}

func NewHandler(s services.ServiceInterface) *Handler {
	return &Handler{service: s}
}

// CreateTokens godoc
// @Summary      Create access and refresh tokens
// @Description  Generate a new pair of tokens (access JWT and refresh base64) for a given user GUID
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        req  body      models.Request  true  "Request body with user GUID"
// @Success      200  {object}  models.Response  "Newly generated tokens"
// @Failure      400  {object}  string           "Bad Request"
// @Failure      500  {object}  string           "Internal Server Error"
// @Router       /create [post]
func (h *Handler) CreateTokens(w http.ResponseWriter, r *http.Request) {
	var req models.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	ua := r.Header.Get("User-Agent")

	access, refresh, err := h.service.GenerateTokens(req.GUID, ip, ua)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := models.Response{AccessToken: access, RefreshToken: refresh}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RefreshTokens godoc
// @Summary      Refresh tokens
// @Description  Refresh an existing pair of tokens by providing valid access JWT and refresh token
// @Tags         auth
// @Produce      json
// @Param        Authorization    header  string  true  "Bearer access token"
// @Param        X-Refresh-Token  header  string  true  "Refresh token in base64"
// @Success      200  {object}  models.Response  "Newly refreshed tokens"
// @Failure      400  {object}  string           "Bad Request"
// @Failure      401  {object}  string           "Unauthorized"
// @Failure      500  {object}  string           "Internal Server Error"
// @Router       /refresh [post]
func (h *Handler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	access := r.Header.Get("Authorization")
	refresh := r.Header.Get("X-Refresh-Token")
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	ua := r.Header.Get("User-Agent")

	newAccess, newRefresh, status, err := h.service.RefreshTokens(access, refresh, ip, ua)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	resp := models.Response{AccessToken: newAccess, RefreshToken: newRefresh}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetCurrentUser godoc
// @Summary      Get current user GUID
// @Description  Retrieve the GUID of the currently authenticated user
// @Tags         auth
// @Produce      json
// @Param        Authorization  header  string  true  "Bearer access token"
// @Success      200  {object}  models.CurrentUserResponse  "User GUID"
// @Failure      401  {object}  string                        "Unauthorized"
// @Router       /me [get]
func (h *Handler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	guid, err := h.service.ValidateAccess(auth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	resp := models.CurrentUserResponse{GUID: guid}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Logout godoc
// @Summary      Logout user (deauthorize)
// @Description  Invalidate all refresh tokens for the current user
// @Tags         auth
// @Produce      json
// @Param        Authorization  header  string  true  "Bearer access token"
// @Success      204  {string}  string  			"No Content"
// @Failure      401  {object}  string             "Unauthorized"
// @Failure      500  {object}  string             "Internal Server Error"
// @Router       /logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	guid, err := h.service.ValidateAccess(auth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := h.service.Logout(guid); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
