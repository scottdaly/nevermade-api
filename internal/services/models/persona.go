package models

import (
	"time"
)

type Persona struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatorID   int       `json:"creator_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (p *Persona) BeforeCreate() {
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
}

func (p *Persona) BeforeUpdate() {
	p.UpdatedAt = time.Now()
}