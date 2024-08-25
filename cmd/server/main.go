// cmd/server/main.go

package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/scottdaly/nevermade-api/internal/api/handlers"
	"github.com/scottdaly/nevermade-api/internal/api/middleware"
	"github.com/scottdaly/nevermade-api/internal/database"
	"github.com/scottdaly/nevermade-api/internal/services"
)

func main() {
	db, err := database.InitDB("./nevermade.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	userService := services.NewUserService(db)
	authHandler := handlers.NewAuthHandler(userService)
	userHandler := handlers.NewUserHandler(userService)

	r := mux.NewRouter()
	
	// Public routes
	r.HandleFunc("/auth/google/login", authHandler.GoogleLogin).Methods("GET")
	r.HandleFunc("/auth/google/callback", authHandler.GoogleCallback).Methods("GET")

	// Protected routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.AuthMiddleware(next.ServeHTTP).ServeHTTP(w, r)
		})
	})

	// User profile route
	api.HandleFunc("/user/profile", userHandler.GetUserProfile).Methods("GET")

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}