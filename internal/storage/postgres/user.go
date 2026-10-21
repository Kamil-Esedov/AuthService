package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/google/uuid"
)

const queryTimeout = 5 * time.Second

func (p *Postgres) Register(ctx context.Context, user *domain.User) (uuid.UUID, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		INSERT INTO users (email, password_hash, role)
		VALUES ($1, $2, $3) RETURNING id;
	`

	if err := p.db.QueryRow(
		ctxTimeout,
		query,
		user.Email,
		user.PasswordHash,
		user.Role,
	).Scan(&user.ID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return uuid.Nil, &domain.AppError{
				Code:    "ErrEmailTaken",
				Message: "email is already taken",
				Status:  http.StatusConflict,
				Cause:   err,
			}
		}
		return uuid.Nil, p.handleError("register user", err)
	}

	return user.ID, nil
}

func (p *Postgres) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, email, password_hash, role, is_verified, is_blocked, created_at, updated_at 
		FROM users
		WHERE email = $1;
	`

	var user domain.User
	if err := p.db.QueryRow(
		ctxTimeout,
		query,
		email,
	).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsVerified,
		&user.IsBlocked,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &domain.AppError{
				Code:    "ErrUserNotFound",
				Message: "user not found",
				Status:  http.StatusNotFound,
				Cause:   err,
			}
		}

		return nil, p.handleError("get user by email", err)
	}

	return &user, nil
}

func (p *Postgres) GetByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, email, password_hash, role, is_verified, is_blocked, created_at, updated_at
		FROM users
		WHERE id = $1;
	`

	var user domain.User
	err := p.db.QueryRow(ctxTimeout, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.IsVerified,
		&user.IsBlocked,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &domain.AppError{
				Code:    "ErrUserNotFound",
				Message: "user not found",
				Status:  http.StatusNotFound,
				Cause:   err,
			}
		}

		return nil, p.handleError("get user by id", err)
	}

	return &user, nil
}
