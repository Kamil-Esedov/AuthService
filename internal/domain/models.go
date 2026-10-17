package domain

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type RegisterInput struct {
	Email    string
	Password string
}

type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	Role         Role
	IsVerified   bool
	IsBlocked    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	UserAgent string
	IP        netip.Addr
	ExpiresAt time.Time
	CreatedAt time.Time
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}
