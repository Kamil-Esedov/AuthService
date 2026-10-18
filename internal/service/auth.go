package service

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Postgres interface {
	Register(ctx context.Context, user *domain.User) (uuid.UUID, error)
	GetByEmail(ctx context.Context, user *domain.User) (*domain.User, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}

type AuthService struct {
	postgres       Postgres
	passwordHasher PasswordHasher
	logger         *zap.Logger
}

func NewAuthService(postgres Postgres, passwordHasher PasswordHasher, logger *zap.Logger) *AuthService {
	return &AuthService{
		postgres:       postgres,
		passwordHasher: passwordHasher,
		logger:         logger,
	}
}

func (s *AuthService) Register(ctx context.Context, data domain.RegisterInput) (uuid.UUID, error) {
	passwordHash, err := s.passwordHasher.Hash(data.Password)
	if err != nil {
		s.logger.Error("failed to hash password", zap.Error(err))

		return uuid.Nil, domain.NewErrInternal(err)
	}

	user := domain.User{
		Email:        data.Email,
		PasswordHash: passwordHash,
	}

	userID, err := s.postgres.Register(ctx, &user)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}

func (s *AuthService) Login(ctx context.Context, data domain.LoginInput) (*domain.User, error) {
	user := &domain.User{
		Email: data.Email,
	}

	user, err := s.postgres.GetByEmail(ctx, user)
	if err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) && appErr.Code == "ErrUnauthorized" {
			s.logger.Info("login failed: invalid credentials")
		}
		return nil, err
	}

	if !s.passwordHasher.Compare(data.Password, user.PasswordHash) {
		s.logger.Info("login failed: invalid credentials")

		return nil, &domain.AppError{
			Code:    "ErrUnauthorized",
			Message: "incorrect email or password",
			Status:  http.StatusUnauthorized,
		}
	}

	return user, nil
}
