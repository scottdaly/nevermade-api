package models

import (
	"time"
)

type Message struct {
	ID         int       `json:"id"`
	UserID     int       `json:"user_id"`
	PersonaID  int       `json:"persona_id"`
	Content    string    `json:"content"`
	IsUserSent bool      `json:"is_user_sent"`
	CreatedAt  time.Time `json:"created_at"`
}

func (m *Message) BeforeCreate() {
	m.CreatedAt = time.Now()
}