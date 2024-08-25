package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

var (
	db     *sql.DB
	config *oauth2.Config
)

func init() {
	// Initialize OAuth config
	config = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
	var clientId = os.Getenv("GOOGLE_CLIENT_ID");
	log.Println("clientId", clientId);
}




func createTables() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			google_id TEXT UNIQUE,
			name TEXT
		);
		CREATE TABLE IF NOT EXISTS characters (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			name TEXT,
			description TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Initialize SQLite database
	var err error
	db, err = sql.Open("sqlite3", "./nevermade.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables if they don't exist
	createTables()

	// Initialize Gin router
	r := gin.Default()

	// Define routes
	r.GET("/auth/google/login", handleGoogleLogin)
	r.GET("/auth/google/callback", handleGoogleCallback)
	r.POST("/character", createCharacter)
	r.GET("/characters", getCharacters)
	r.POST("/chat", chatWithCharacter)

	// Run the server
	r.Run(":8080")
}

func handleGoogleLogin(c *gin.Context) {
	url := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGoogleCallback(c *gin.Context) {
	var request struct {
		IDToken string `json:"idToken"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Verify the ID token
	payload, err := idtoken.Validate(context.Background(), request.IDToken, os.Getenv("GOOGLE_CLIENT_ID"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid ID token"})
		return
	}

	// Extract user information from the payload
	googleID := payload.Subject
	name, _ := payload.Claims["name"].(string)

	// Check if user exists, if not, create new user
	user, err := getOrCreateUser(googleID, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user"})
		return
	}

	// Here you would typically create a session or JWT for the user
	// For simplicity, we're just returning the user ID
	c.JSON(http.StatusOK, gin.H{"userId": user.ID})
}

func getUserInfo(client *http.Client) (*UserInfo, error) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo UserInfo
	err = json.Unmarshal(data, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func getOrCreateUser(googleID, name string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, google_id, name FROM users WHERE google_id = ?", googleID).Scan(&user.ID, &user.GoogleID, &user.Name)
	if err == sql.ErrNoRows {
		// User doesn't exist, create new user
		result, err := db.Exec("INSERT INTO users (google_id, name) VALUES (?, ?)", googleID, name)
		if err != nil {
			return nil, err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}
		user = User{ID: id, GoogleID: googleID, Name: name}
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

type UserInfo struct {
	ID    string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type User struct {
	ID       int64
	GoogleID string
	Name     string
}


func createCharacter(c *gin.Context) {
	// Implement character creation logic
	c.JSON(http.StatusOK, gin.H{"message": "Character created successfully"})
}

func getCharacters(c *gin.Context) {
	// Implement fetching characters logic
	c.JSON(http.StatusOK, gin.H{"message": "Characters fetched successfully"})
}

func chatWithCharacter(c *gin.Context) {
	// Implement chat functionality
	c.JSON(http.StatusOK, gin.H{"message": "Chat message sent successfully"})
}
