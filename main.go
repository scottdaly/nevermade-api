package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"encoding/gob"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest represents the incoming chat request
type ChatRequest struct {
	Messages []Message `json:"messages"`
}

// ChatResponse represents the API response
type ChatResponse struct {
	Reply string `json:"reply"`
}

// AnthropicRequest represents the request structure for Anthropic API
type AnthropicRequest struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens"`
}

// AnthropicResponse represents the response structure from Anthropic API
type AnthropicResponse struct {
    ID      string `json:"id"`
    Type    string `json:"type"`
    Role    string `json:"role"`
    Model   string `json:"model"`
    Content []struct {
        Type string `json:"type"`
        Text string `json:"text"`
    } `json:"content"`
    StopReason string `json:"stop_reason"`
    Usage      struct {
        InputTokens  int `json:"input_tokens"`
        OutputTokens int `json:"output_tokens"`
    } `json:"usage"`
}

const anthropicAPI = "https://api.anthropic.com/v1/messages"

var (
    googleOauthConfig *oauth2.Config
    oauthStateString  = "random"
    store *sessions.CookieStore
	db *sql.DB
)

// New types for database entities
type Character struct {
	ID          int    `json:"id"`
	UserID      string `json:"user_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ImageURL    string `json:"image_url"`
}

type Conversation struct {
	ID          int    `json:"id"`
	UserID      string `json:"user_id"`
	CharacterID int    `json:"character_id"`
	Title       string `json:"title"`
}

type ConversationMessage struct {
	ID             int    `json:"id"`
	ConversationID int    `json:"conversation_id"`
	Role           string `json:"role"`
	Content        string `json:"content"`
}

func getRedirectURL(r *http.Request) string {
    origin := r.Header.Get("Origin")
    if strings.HasPrefix(origin, "http://localhost") {
        return "http://localhost:5173/api/callback"
    }
    return "https://nevermade.co/api/callback"
}

func init() {
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    // Initialize the sessions store
    sessionKey := os.Getenv("SESSION_KEY")
    if sessionKey == "" {
        log.Fatal("SESSION_KEY must be set")
    }
    store = sessions.NewCookieStore([]byte(sessionKey))

    // Initialize Google OAuth config
    clientID := os.Getenv("GOOGLE_CLIENT_ID")
    clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
    if clientID == "" || clientSecret == "" {
        log.Fatal("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set")
    }

    googleOauthConfig = &oauth2.Config{
        RedirectURL:  "https://nevermade.co/api/callback",
        ClientID:     clientID,
        ClientSecret: clientSecret,
        Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
        Endpoint:     google.Endpoint,
    }

    // Register complex data types for storage in sessions
    gob.Register(map[string]interface{}{})

	// Initialize SQLite database
	db, err = sql.Open("sqlite3", "./nevermade.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tables if they don't exist
	createTables()
}

func createTables() {
	// Create characters table
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS characters (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT,
		name TEXT,
		description TEXT,
		image_url TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Create conversations table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS conversations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT,
		character_id INTEGER,
		title TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Create conversation_messages table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS conversation_messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		conversation_id INTEGER,
		role TEXT,
		content TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	googleOauthConfig.RedirectURL = getRedirectURL(r)
    url := googleOauthConfig.AuthCodeURL(oauthStateString)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	googleOauthConfig.RedirectURL = getRedirectURL(r)
    content, err := getUserInfo(r.FormValue("state"), r.FormValue("code"))
    if err != nil {
        log.Printf("Error getting user info: %v", err)
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return
    }

    var userInfo map[string]interface{}
    if err := json.Unmarshal(content, &userInfo); err != nil {
        log.Printf("Error unmarshalling user info: %v", err)
        http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
        return
    }

    // Create a session
    session, _ := store.Get(r, "session-name")
    session.Values["user"] = userInfo
    session.Save(r, w)

    // Redirect based on the origin
    if strings.HasPrefix(r.Header.Get("Origin"), "http://localhost") {
        http.Redirect(w, r, "http://localhost:5173", http.StatusTemporaryRedirect)
    } else {
        http.Redirect(w, r, "https://nevermade.co", http.StatusTemporaryRedirect)
    }
}

func handleCheckSession(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
    if user, ok := session.Values["user"].(map[string]interface{}); ok {
        json.NewEncoder(w).Encode(user)
    } else {
        http.Error(w, "Not logged in", http.StatusUnauthorized)
    }
}

func getUserInfo(state string, code string) ([]byte, error) {
    if state != oauthStateString {
        return nil, fmt.Errorf("invalid oauth state")
    }

    token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
    if err != nil {
        return nil, fmt.Errorf("code exchange failed: %s", err.Error())
    }

    response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
    if err != nil {
        return nil, fmt.Errorf("failed getting user info: %s", err.Error())
    }

    defer response.Body.Close()
    contents, err := io.ReadAll(response.Body)
    if err != nil {
        return nil, fmt.Errorf("failed reading response body: %s", err.Error())
    }

    return contents, nil
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
    user, ok := session.Values["user"].(map[string]interface{})
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    json.NewEncoder(w).Encode(user)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
    session.Values["user"] = nil
    session.Save(r, w)
    w.WriteHeader(http.StatusOK)
}

// handleChat processes the chat request
func handleChat(w http.ResponseWriter, r *http.Request) {
    log.Println("Received chat request")

    var req ChatRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        log.Printf("Error decoding request: %v", err)
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    log.Printf("Decoded request: %+v", req)

    // Prepare request for Anthropic API
    anthropicReq := AnthropicRequest{
        Model:     "claude-3-sonnet-20240229",
        Messages:  req.Messages,
        MaxTokens: 4000,
    }

    anthropicReqBody, err := json.Marshal(anthropicReq)
    if err != nil {
        log.Printf("Error marshaling Anthropic request: %v", err)
        http.Error(w, "Failed to marshal Anthropic request", http.StatusInternalServerError)
        return
    }
    log.Printf("Anthropic request body: %s", string(anthropicReqBody))

    // Send request to Anthropic API
    client := &http.Client{}
    anthropicReqHttp, err := http.NewRequest("POST", anthropicAPI, bytes.NewBuffer(anthropicReqBody))
    if err != nil {
        log.Printf("Error creating Anthropic request: %v", err)
        http.Error(w, "Failed to create Anthropic request", http.StatusInternalServerError)
        return
    }

    anthropicReqHttp.Header.Set("Content-Type", "application/json")
    anthropicReqHttp.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
    anthropicReqHttp.Header.Set("anthropic-version", "2023-06-01")

    log.Println("Sending request to Anthropic API")
    anthropicResp, err := client.Do(anthropicReqHttp)
    if err != nil {
        log.Printf("Error sending request to Anthropic: %v", err)
        http.Error(w, "Failed to send request to Anthropic", http.StatusInternalServerError)
        return
    }
    defer anthropicResp.Body.Close()

    log.Printf("Received response from Anthropic. Status: %s", anthropicResp.Status)
    body, err := io.ReadAll(anthropicResp.Body)
    if err != nil {
        log.Printf("Error reading Anthropic response: %v", err)
        http.Error(w, "Failed to read Anthropic response", http.StatusInternalServerError)
        return
    }

    log.Printf("Raw Anthropic response: %s", string(body))

    var anthropicResponse AnthropicResponse
    err = json.Unmarshal(body, &anthropicResponse)
    if err != nil {
        log.Printf("Error parsing Anthropic response: %v", err)
        http.Error(w, "Failed to parse Anthropic response", http.StatusInternalServerError)
        return
    }

    log.Printf("Parsed Anthropic response: %+v", anthropicResponse)

    if len(anthropicResponse.Content) == 0 {
        log.Println("Empty content in Anthropic response")
        http.Error(w, "Empty response from Anthropic", http.StatusInternalServerError)
        return
    }

    response := ChatResponse{
        Reply: "Gooood " + anthropicResponse.Content[0].Text,
    }

    log.Printf("Sending response: %+v", response)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)

	// After getting the response from Anthropic API
	// Save the message to the database
	conversationID := r.URL.Query().Get("conversation_id")
	_, err = db.Exec("INSERT INTO conversation_messages (conversation_id, role, content) VALUES (?, ?, ?)",
		conversationID, "assistant", response.Reply)
	if err != nil {
		log.Printf("Error saving message to database: %v", err)
	}
}

func handleCreateCharacter(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling create character request")

	// Get user from session
	session, _ := store.Get(r, "session-name")
	user, ok := session.Values["user"].(map[string]interface{})
	if !ok {
		log.Println("User not found in session")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Printf("User ID from session: %v", user["id"])

	var character Character
	err := json.NewDecoder(r.Body).Decode(&character)
	if err != nil {
		log.Printf("Error decoding character data: %v", err)
		http.Error(w, "Invalid character data", http.StatusBadRequest)
		return
	}
	log.Printf("Decoded character: %+v", character)

	character.UserID = user["id"].(string)

	log.Println("Attempting to insert character into database")
	result, err := db.Exec("INSERT INTO characters (user_id, name, description, image_url) VALUES (?, ?, ?, ?)",
		character.UserID, character.Name, character.Description, character.ImageURL)
	if err != nil {
		log.Printf("Error inserting character into database: %v", err)
		http.Error(w, "Failed to create character", http.StatusInternalServerError)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last insert ID: %v", err)
		http.Error(w, "Failed to get character ID", http.StatusInternalServerError)
		return
	}
	character.ID = int(id)
	log.Printf("Character created with ID: %d", character.ID)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(character)
	if err != nil {
		log.Printf("Error encoding character response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	log.Println("Character creation successful")
}

func handleGetCharacters(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	session, _ := store.Get(r, "session-name")
	user, ok := session.Values["user"].(map[string]interface{})
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT id, name, description, image_url FROM characters WHERE user_id = ?", user["id"].(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var characters []Character
	for rows.Next() {
		var c Character
		err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.ImageURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		characters = append(characters, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(characters)
}

func handleCreateConversation(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	session, _ := store.Get(r, "session-name")
	user, ok := session.Values["user"].(map[string]interface{})
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var conversation Conversation
	err := json.NewDecoder(r.Body).Decode(&conversation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conversation.UserID = user["id"].(string)

	result, err := db.Exec("INSERT INTO conversations (user_id, character_id, title) VALUES (?, ?, ?)",
		conversation.UserID, conversation.CharacterID, conversation.Title)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	conversation.ID = int(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conversation)
}

func handleGetConversations(w http.ResponseWriter, r *http.Request) {
	// Get user from session
	session, _ := store.Get(r, "session-name")
	user, ok := session.Values["user"].(map[string]interface{})
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(`
		SELECT c.id, c.character_id, c.title, ch.name AS character_name 
		FROM conversations c
		JOIN characters ch ON c.character_id = ch.id
		WHERE c.user_id = ?`, user["id"].(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ConversationWithCharacter struct {
		Conversation
		CharacterName string `json:"character_name"`
	}

	var conversations []ConversationWithCharacter
	for rows.Next() {
		var c ConversationWithCharacter
		err := rows.Scan(&c.ID, &c.CharacterID, &c.Title, &c.CharacterName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		conversations = append(conversations, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conversations)
}

func handleGetConversationMessages(w http.ResponseWriter, r *http.Request) {
    log.Println("Handling get conversation messages request")
    log.Printf("Request URL: %s", r.URL.String())
    log.Printf("Request Headers: %v", r.Header)

    // Get user from session
    session, _ := store.Get(r, "session-name")
    user, ok := session.Values["user"].(map[string]interface{})
    if !ok {
        log.Println("User not found in session")
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    log.Printf("User ID from session: %v", user["id"])

    vars := mux.Vars(r)
    conversationID := vars["id"]
    log.Printf("Fetching messages for conversation ID: %s", conversationID)

    // Verify that the conversation belongs to the user
    var count int
    err := db.QueryRow("SELECT COUNT(*) FROM conversations WHERE id = ? AND user_id = ?", 
        conversationID, user["id"].(string)).Scan(&count)
    if err != nil {
        log.Printf("Error checking conversation ownership: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if count == 0 {
        log.Printf("Conversation not found or unauthorized for user %s", user["id"])
        http.Error(w, "Conversation not found or unauthorized", http.StatusNotFound)
        return
    }

    rows, err := db.Query("SELECT id, role, content FROM conversation_messages WHERE conversation_id = ? ORDER BY id", conversationID)
    if err != nil {
        log.Printf("Error querying conversation messages: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var messages []ConversationMessage
    for rows.Next() {
        var m ConversationMessage
        err := rows.Scan(&m.ID, &m.Role, &m.Content)
        if err != nil {
            log.Printf("Error scanning message row: %v", err)
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }
        messages = append(messages, m)
    }

    log.Printf("Retrieved %d messages for conversation %s", len(messages), conversationID)

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(messages); err != nil {
        log.Printf("Error encoding messages to JSON: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    log.Println("Successfully sent conversation messages")
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/chat", handleChat).Methods("POST")
	r.HandleFunc("/login", handleGoogleLogin)
	r.HandleFunc("/callback", handleGoogleCallback)
	r.HandleFunc("/api/user", handleUserInfo).Methods("GET")
	r.HandleFunc("/check-session", handleCheckSession)
	r.HandleFunc("/logout", handleLogout).Methods("POST")
	r.HandleFunc("/characters", handleCreateCharacter).Methods("POST")
	r.HandleFunc("/characters", handleGetCharacters).Methods("GET")
    r.HandleFunc("/conversations", handleCreateConversation).Methods("POST")
    r.HandleFunc("/conversations", handleGetConversations).Methods("GET")
    r.HandleFunc("/conversations/{id}/messages", handleGetConversationMessages).Methods("GET")

	    // Create a CORS middleware
	c := cors.New(cors.Options{
            AllowedOrigins: []string{"https://nevermade.co"},
            AllowedMethods: []string{"GET", "POST", "OPTIONS"},
            AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

    	// Print database schema
	rows, err := db.Query("SELECT sql FROM sqlite_master WHERE type='table'")
	if err != nil {
		log.Fatalf("Error querying database schema: %v", err)
	}
	defer rows.Close()

	log.Println("Database Schema:")
	for rows.Next() {
		var sql string
		if err := rows.Scan(&sql); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		log.Println(sql)
	}

	handler := c.Handler(r)

	log.Println("Server starting on localhost:8080")
	log.Fatal(http.ListenAndServe("localhost:8080", handler))
}