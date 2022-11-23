package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"centre/config"
	"centre/model"
	"centre/server"
	"centre/token"

	"github.com/gorilla/schema"
	"gorm.io/gorm"
)

type renewAccessTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type renewAccessTokenResponse struct {
	AccessToken         string    `json:"access_token"`
	AccessTokenExpireAt time.Time `json:"access_token_expire_at"`
}

type tokenVerificationRequest struct {
	AccessToken string `json:"accessToken"`
}

type tokenVerificationResponse struct {
	Status uint `json:"status"`
	Valid  bool `json:"is_valid"`
}

func VerifyToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	var req tokenVerificationRequest
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = schema.NewDecoder().Decode(&req, r.Form)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	maker, err := token.NewJWTMaker(config.Config.TokenSymmetricKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = maker.VerifyToken(req.AccessToken)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenVerificationResponse{
		Status: http.StatusOK,
		Valid:  true,
	})
}

func HandleRenewAccessToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	var req renewAccessTokenRequest
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = schema.NewDecoder().Decode(&req, r.Form)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	maker, err := token.NewJWTMaker(config.Config.TokenSymmetricKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	refreshPayload, err := maker.VerifyToken(req.RefreshToken)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var session model.CtrUsrSss
	DB := server.DB
	err = DB.Last(&session, "email = ? AND id = ?", refreshPayload.Email, refreshPayload.ID).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsBlck {
		err = fmt.Errorf("Blocked Session")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if session.Email != refreshPayload.Email {
		err = fmt.Errorf("Incorrect Session User")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if session.RfhTkn != req.RefreshToken {
		err = fmt.Errorf("Mismatch Session Token")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if time.Now().After(session.ExpAt) {
		err = fmt.Errorf("Expired Session")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	accessToken, accessTokenPayload, err := maker.CreateToken(refreshPayload.Email, config.Config.AccessTokenDuration)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(renewAccessTokenResponse{
		AccessToken:         accessToken,
		AccessTokenExpireAt: accessTokenPayload.ExpiredAt,
	})
}
