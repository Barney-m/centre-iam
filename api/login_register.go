package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"centre/config"
	"centre/model"
	"centre/server"
	"centre/token"
	"centre/util"

	"github.com/google/uuid"
	"github.com/gorilla/schema"
	"gorm.io/gorm"
)

type registerUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullNm   string `json:"full_name" schema:"full_name"`
	Dob      string `json:"dob"`
	Addr     string `json:"address"`
	MobileNo string `json:"mobile_no"`
	Rank     string `json:"rank"`
}

type registerUserResponse struct {
	UsrId    uuid.UUID `gorm:"primaryKey" json:"user_id"`
	Email    string    `json:"email"`
	FullNm   string    `json:"full_name"`
	Addr     string    `json:"address"`
	Dob      time.Time `json:"dob"`
	Rnk      string    `json:"rank"`
	MblNo    string    `json:"mobile_no"`
	UsrSts   string    `json:"user_status"`
	IsFrtIdc bool      `json:"is_frt_idc"`
}

type loginUserRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
}

type loginUserResponse struct {
	SessionId            uuid.UUID     `json:"session_id"`
	AccessToken          string        `json:"access_token"`
	AccessTokenExpireAt  time.Time     `json:"access_token_expire_at"`
	RefreshToken         string        `json:"refresh_token"`
	RefreshTokenExpireAt time.Time     `json:"refresh_token_expire_at"`
	User                 *model.CtrUsr `json:"user"`
}

func HandleLoginRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	var credentials loginUserRequest
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = schema.NewDecoder().Decode(&credentials, r.Form)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var user model.CtrUsr
	var userSecret model.CtrUsrSct
	DB := server.DB
	err = DB.Last(&user, "email = ?", credentials.Email).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  http.StatusInternalServerError,
				"message": "User Not Found",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  http.StatusInternalServerError,
				"message": err.Error(),
			})
		}
		return
	}

	DB.Last(&userSecret, "usr_id = ?", user.UsrId)

	isMatch, err := util.VldPassword(credentials.Password, userSecret.Pwd)

	if err != nil || !isMatch {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": "Invalid Email / Password",
		})
		return
	}

	tokenMaker, err := token.NewJWTMaker(config.Config.TokenSymmetricKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": "Failed to Login",
		})
		return
	}

	accessToken, accessPayload, err := tokenMaker.CreateToken(user.Email, config.Config.AccessTokenDuration)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	refreshToken, refreshPayload, err := tokenMaker.CreateToken(user.Email, config.Config.RefreshTokenDuration)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	err = DB.Transaction(func(tx *gorm.DB) error {
		xForward := r.Header.Get("X-Forwarded-For")

		if xForward == "" {
			xForward = r.RemoteAddr
		}

		userSession := &model.CtrUsrSss{
			SssId:  refreshPayload.ID,
			Email:  user.Email,
			RfhTkn: refreshToken,
			UsrAgt: r.UserAgent(),
			CltIp:  xForward,
			ExpAt:  refreshPayload.ExpiredAt,
		}

		if err := tx.Create(&userSession).Error; err != nil {
			// return any error will rollback
			return err
		}

		return nil
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": http.StatusOK,
		"result": loginUserResponse{
			SessionId:            refreshPayload.ID,
			AccessToken:          accessToken,
			AccessTokenExpireAt:  accessPayload.ExpiredAt,
			RefreshToken:         refreshToken,
			RefreshTokenExpireAt: refreshPayload.ExpiredAt,
			User:                 &user,
		},
	})
}

// Register
func HandleRegisterRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	var userRequest registerUserRequest

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = schema.NewDecoder().Decode(&userRequest, r.Form)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(userRequest.Email) < 1 || len(userRequest.Password) < 1 {
		http.Error(w, "Email / Password is required", http.StatusBadRequest)
		return
	}

	p := &util.Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	// Connect DB
	DB := server.DB

	newUuid, _ := uuid.NewRandom()
	print(userRequest.Dob)
	dob, err := time.Parse("2006-01-02", userRequest.Dob)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Set User to be create
	// Rollback if error
	user := &model.CtrUsr{
		UsrId:  newUuid,
		FullNm: userRequest.FullNm,
		Email:  userRequest.Email,
		Addr:   userRequest.Addr,
		Dob:    dob,
		MblNo:  userRequest.MobileNo,
		UsrSts: "A",
	}

	// Start DB Transaction
	err = DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			// return any error will rollback
			return err
		}

		hashedPassword, salt, err := util.HashPassword(userRequest.Password, p)

		if err != nil {
			return err
		}

		userSecret := &model.CtrUsrSct{
			UsrId: user.UsrId,
			Usrnm: userRequest.Email,
			Pwd:   hashedPassword,
			Salt:  salt,
		}

		if err := tx.Create(&userSecret).Error; err != nil {
			// return any error will rollback
			return err
		}

		return nil
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to Register")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": http.StatusOK,
		"result": registerUserResponse{
			UsrId:    user.UsrId,
			Email:    user.Email,
			FullNm:   user.FullNm,
			Addr:     user.Addr,
			Dob:      dob,
			MblNo:    user.MblNo,
			Rnk:      user.Rnk,
			UsrSts:   user.UsrSts,
			IsFrtIdc: user.IsFrtIdc,
		},
	})
}
