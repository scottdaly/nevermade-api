package services

import (
	"database/sql"

	"github.com/scottdaly/nevermade-api/internal/models"
)

type PersonaService struct {
	DB *sql.DB
}

func NewPersonaService(db *sql.DB) *PersonaService {
	return &PersonaService{DB: db}
}

func (s *PersonaService) CreatePersona(persona *models.Persona) error {
	persona.BeforeCreate()

	result, err := s.DB.Exec(
		"INSERT INTO personas (name, description, creator_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		persona.Name, persona.Description, persona.CreatorID, persona.CreatedAt, persona.UpdatedAt,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	persona.ID = int(id)
	return nil
}

func (s *PersonaService) GetPersonas() ([]*models.Persona, error) {
	rows, err := s.DB.Query("SELECT id, name, description, creator_id, created_at, updated_at FROM personas")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var personas []*models.Persona
	for rows.Next() {
		persona := &models.Persona{}
		err := rows.Scan(
			&persona.ID, &persona.Name, &persona.Description,
			&persona.CreatorID, &persona.CreatedAt, &persona.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		personas = append(personas, persona)
	}

	return personas, nil
}