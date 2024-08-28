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
)

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
        Reply: anthropicResponse.Content[0].Text,
    }

    log.Printf("Sending response: %+v", response)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/chat", handleChat).Methods("POST")
	r.HandleFunc("/login", handleGoogleLogin)
	r.HandleFunc("/callback", handleGoogleCallback)
	r.HandleFunc("/api/user", handleUserInfo).Methods("GET")
	r.HandleFunc("/check-session", handleCheckSession)
	r.HandleFunc("/logout", handleLogout).Methods("POST")

	    // Create a CORS middleware
	c := cors.New(cors.Options{
            AllowedOrigins: []string{"https://nevermade.co"},
            AllowedMethods: []string{"GET", "POST", "OPTIONS"},
            AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

	handler := c.Handler(r)

	log.Println("Server starting on localhost:8080")
	log.Fatal(http.ListenAndServe("localhost:8080", handler))
}