package httpTransport

import (
	"auth-service/internal/domain"
	"time"

	"github.com/google/uuid"
)

type RegisterRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type LoginRequestDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type RegisterResponseDTO struct {
	ID uuid.UUID `json:"id"`
}

type LoginResponseDTO struct {
	User UserResponseDTO `json:"user"`
}

type UserResponseDTO struct {
	ID         uuid.UUID
	Email      string
	Role       domain.Role
	IsVerified bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
