package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func HandleAuthRequest(r *mux.Router) {
	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/login", HandleLoginRequest).Methods(http.MethodPost)
	authRouter.HandleFunc("/register", HandleRegisterRequest).Methods(http.MethodPost)
	authRouter.HandleFunc("/token/verifyAccess", VerifyToken).Methods(http.MethodPost)
	authRouter.HandleFunc("/token/renewAccess", HandleRenewAccessToken).Methods(http.MethodPost)
}
