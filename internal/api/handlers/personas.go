package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/scottdaly/nevermade-api/internal/database"
	"github.com/scottdaly/nevermade-api/internal/models"
)

func CreatePersona(w http.ResponseWriter, r *http.Request) {
	var persona models.Persona
	err := json.NewDecoder(r.Body).Decode(&persona)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// You might want to get the creator ID from the authenticated user in the request context
	creatorID := 1 // Placeholder, replace with actual creator ID

	db := database.GetDB()
	result, err := db.Exec("INSERT INTO personas (name, description, creator_id) VALUES (?, ?, ?)",
		persona.Name, persona.Description, creatorID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	persona.ID = int(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(persona)
}

func GetPersonas(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()
	rows, err := db.Query("SELECT id, name, description, creator_id FROM personas")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var personas []models.Persona
	for rows.Next() {
		var p models.Persona
		err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatorID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		personas = append(personas, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(personas)
}