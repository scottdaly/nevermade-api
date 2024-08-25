package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/scottdaly/nevermade-api/internal/database"
	"github.com/scottdaly/nevermade-api/internal/models"
)

func SendMessage(w http.ResponseWriter, r *http.Request) {
	var message models.Message
	err := json.NewDecoder(r.Body).Decode(&message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// You might want to get the user ID from the authenticated user in the request context
	userID := 1 // Placeholder, replace with actual user ID

	db := database.GetDB()
	result, err := db.Exec("INSERT INTO messages (user_id, persona_id, content, is_user_sent) VALUES (?, ?, ?, ?)",
		userID, message.PersonaID, message.Content, message.IsUserSent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	message.ID = int(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
}

func GetMessages(w http.ResponseWriter, r *http.Request) {
	personaID := r.URL.Query().Get("persona_id")
	if personaID == "" {
		http.Error(w, "Missing persona_id parameter", http.StatusBadRequest)
		return
	}

	db := database.GetDB()
	rows, err := db.Query("SELECT id, user_id, persona_id, content, is_user_sent FROM messages WHERE persona_id = ?", personaID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []models.Message
	for rows.Next() {
		var m models.Message
		err := rows.Scan(&m.ID, &m.UserID, &m.PersonaID, &m.Content, &m.IsUserSent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		messages = append(messages, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}