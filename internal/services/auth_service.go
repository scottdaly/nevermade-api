package services

import (
	"database/sql"

	"github.com/scottdaly/nevermade-api/internal/models"
)

type AuthService struct {
	DB *sql.DB
}

func (s *AuthService) AuthenticateUser(email string) (*models.User, error) {
	// Implementation to find or create user based on email
}