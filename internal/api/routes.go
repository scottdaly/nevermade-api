package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/scottdaly/nevermade-api/internal/api/handlers"
	"github.com/scottdaly/nevermade-api/internal/api/middleware"
)

func SetupRoutes(r *mux.Router) {
	// Apply logging middleware to all routes
	r.Use(func(next http.Handler) http.Handler {
		return middleware.LoggingMiddleware(next.ServeHTTP)
	})

	// Public routes
	// r.HandleFunc("/auth/google/login", handlers.HandleGoogleLogin).Methods("GET")
	// r.HandleFunc("/auth/google/callback", handlers.HandleGoogleCallback).Methods("GET")
	// r.HandleFunc("/users", handlers.CreateUser).Methods("POST")

	// Protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(func(next http.Handler) http.Handler {
		return middleware.AuthMiddleware(next.ServeHTTP)
	})

	// protected.HandleFunc("/users/{id}", handlers.GetUser).Methods("GET")
	protected.HandleFunc("/personas", handlers.CreatePersona).Methods("POST")
	protected.HandleFunc("/personas", handlers.GetPersonas).Methods("GET")
	protected.HandleFunc("/messages", handlers.SendMessage).Methods("POST")
	protected.HandleFunc("/messages", handlers.GetMessages).Methods("GET")
}