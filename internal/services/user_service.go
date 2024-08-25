// internal/services/user_service.go

package services

import (
	"database/sql"
	"time"

	"github.com/scottdaly/nevermade-api/internal/models"
)

type UserService struct {
	DB *sql.DB
}

func NewUserService(db *sql.DB) *UserService {
	return &UserService{DB: db}
}

func (s *UserService) CreateOrUpdateUser(googleUser *models.GoogleUser) (*models.User, error) {
	var user models.User
	err := s.DB.QueryRow("SELECT id, email, name, picture, created_at, updated_at FROM users WHERE google_id = ?", googleUser.ID).
		Scan(&user.ID, &user.Email, &user.Name, &user.Picture, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		// User doesn't exist, create a new one
		user = models.User{
			GoogleID: googleUser.ID,
			Email:    googleUser.Email,
			Name:     googleUser.Name,
			Picture:  googleUser.Picture,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		result, err := s.DB.Exec(
			"INSERT INTO users (google_id, email, name, picture, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			user.GoogleID, user.Email, user.Name, user.Picture, user.CreatedAt, user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		id, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}
		user.ID = int(id)
	} else if err != nil {
		return nil, err
	} else {
		// User exists, update their information
		user.GoogleID = googleUser.ID
		user.Email = googleUser.Email
		user.Name = googleUser.Name
		user.Picture = googleUser.Picture
		user.UpdatedAt = time.Now()

		_, err = s.DB.Exec(
			"UPDATE users SET email = ?, name = ?, picture = ?, updated_at = ? WHERE google_id = ?",
			user.Email, user.Name, user.Picture, user.UpdatedAt, user.GoogleID,
		)
		if err != nil {
			return nil, err
		}
	}

	return &user, nil
}

func (s *UserService) GetUserByID(id int) (*models.User, error) {
	var user models.User
	err := s.DB.QueryRow("SELECT id, google_id, email, name, picture, created_at, updated_at FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.Picture, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}