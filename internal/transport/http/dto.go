package httpTransport

import (
	"auth-service/internal/domain"
	"time"

	"github.com/google/uuid"
)

type RegisterRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

type LoginRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RegisterResponseDTO struct {
	ID uuid.UUID `json:"id"`
}

type TokenPairResponseDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequestDTO struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type LogoutRequestDTO struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type UserResponseDTO struct {
	ID         uuid.UUID   `json:"id"`
	Email      string      `json:"email"`
	Role       domain.Role `json:"role"`
	IsVerified bool        `json:"is_verified"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}
