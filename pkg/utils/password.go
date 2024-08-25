package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// The minimum cost to use for hashing. Higher cost means more secure but slower.
	MinCost = 10
	// The maximum cost to use for hashing. A sensible upper limit.
	MaxCost = 31
)

// HashPassword takes a plain-text password and returns a bcrypt hash of it.
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password cannot be empty")
	}

	// Generate a bcrypt hash using the default cost (10)
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

// VerifyPassword compares a plain-text password with a bcrypt hashed password.
// It returns nil on success, or an error on failure.
func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateRandomPassword generates a cryptographically secure random password.
func GenerateRandomPassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New("password length must be at least 8 characters")
	}

	// We need 6 bits per character for base64, so we need to generate length*6/8 bytes
	bytes := make([]byte, (length*6+7)/8)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert to base64
	password := base64.RawURLEncoding.EncodeToString(bytes)

	// Trim to the requested length
	return password[:length], nil
}

// IsPasswordStrong checks if a password meets certain strength criteria.
func IsPasswordStrong(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case 'a' <= char && char <= 'z':
			hasLower = true
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}