package services

import (
	"database/sql"

	"github.com/scottdaly/nevermade-api/internal/models"
)

type MessageService struct {
	DB *sql.DB
}

func NewMessageService(db *sql.DB) *MessageService {
	return &MessageService{DB: db}
}

func (s *MessageService) CreateMessage(message *models.Message) error {
	message.BeforeCreate()

	result, err := s.DB.Exec(
		"INSERT INTO messages (user_id, persona_id, content, is_user_sent, created_at) VALUES (?, ?, ?, ?, ?)",
		message.UserID, message.PersonaID, message.Content, message.IsUserSent, message.CreatedAt,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	message.ID = int(id)
	return nil
}

func (s *MessageService) GetMessagesByPersona(personaID int) ([]*models.Message, error) {
	rows, err := s.DB.Query(
		"SELECT id, user_id, persona_id, content, is_user_sent, created_at FROM messages WHERE persona_id = ? ORDER BY created_at",
		personaID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*models.Message
	for rows.Next() {
		message := &models.Message{}
		err := rows.Scan(
			&message.ID, &message.UserID, &message.PersonaID,
			&message.Content, &message.IsUserSent, &message.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}

	return messages, nil
}