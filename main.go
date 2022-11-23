package main

import (
	"net/http"
	"time"

	"centre/api"
	"centre/server"

	"github.com/gorilla/mux"
)

func main() {
	initHttpServer()
}

func initHttpServer() {
	serverChan := make(chan error)
	go server.LoadConfig(serverChan)

	err := <-serverChan
	if err != nil {
		panic(err)
	}

	go server.ConnectDB(serverChan)
	err = <-serverChan
	if err != nil {
		panic(err)
	}

	router := mux.NewRouter()
	subRouter := router.PathPrefix("/centre/iam").Subrouter()
	api.HandleAuthRequest(subRouter)

	srv := &http.Server{
		Handler: subRouter,
		Addr:    ":8190",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	srv.ListenAndServe()
}
