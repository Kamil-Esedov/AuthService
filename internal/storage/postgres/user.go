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
	"go.uber.org/zap"
)

func (p *Postgres) Register(ctx context.Context, user *domain.User) (uuid.UUID, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2) RETURNING id;
	`

	if err := p.db.QueryRow(
		ctxTimeout,
		query,
		user.Email,
		user.PasswordHash,
	).Scan(&user.ID); err != nil {
		if errors.Is(err, context.Canceled) {
			return uuid.Nil, &domain.AppError{
				Code:    "ErrContextCanceled",
				Message: "context canceled by client",
				Status:  499,
				Cause:   err,
			}
		}

		if errors.Is(err, context.DeadlineExceeded) {
			p.logger.Error(
				"postgres query timeout",
				zap.String("operation", "register user"),
				zap.Duration("timeout", 5*time.Second),
				zap.Error(err),
			)

			return uuid.Nil, &domain.AppError{
				Code:    "ErrTimeout",
				Message: "database query timed out",
				Status:  http.StatusGatewayTimeout,
				Cause:   err,
			}
		}

		if errors.Is(err, pgx.ErrNoRows) {
			p.logger.Error(
				"postgres insert returned no user ID",
				zap.String("operation", "register user"),
				zap.Error(err),
			)

			return uuid.Nil, domain.NewErrInternal(err)
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return uuid.Nil, &domain.AppError{
					Code:    "ErrEmailTaken",
					Message: "email is already taken",
					Status:  http.StatusConflict,
					Cause:   err,
				}
			case "23503":
				p.logger.Error(
					"foreign key violation",
					zap.String("operation", "register user"),
					zap.String("constraint", pgErr.ConstraintName),
					zap.Error(err),
				)

				return uuid.Nil, domain.NewErrInternal(err)
			default:
				p.logger.Error(
					"postgres query failed",
					zap.String("operation", "register user"),
					zap.String("code", string(pgErr.Code)),
					zap.String("constraint", pgErr.ConstraintName),
					zap.Error(err),
				)

				return uuid.Nil, domain.NewErrInternal(err)
			}
		}

		p.logger.Error(
			"postgres query failed",
			zap.String("operation", "register user"),
			zap.Error(err),
		)

		return uuid.Nil, domain.NewErrInternal(err)
	}

	return user.ID, nil
}

func (p *Postgres) GetByEmail(ctx context.Context, user *domain.User) (*domain.User, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, email, password_hash, role, is_verified, is_blocked, created_at, updated_at 
			FROM users
		WHERE email = $1;
	`

	if err := p.db.QueryRow(
		ctxTimeout,
		query,
		user.Email,
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
				Code:    "ErrUnauthorized",
				Message: "incorrect email or password",
				Status:  http.StatusUnauthorized,
				Cause:   err,
			}
		}

		if errors.Is(err, context.Canceled) {
			return nil, &domain.AppError{
				Code:    "ErrContextCanceled",
				Message: "context canceled by client",
				Status:  499,
				Cause:   err,
			}
		}

		if errors.Is(err, context.DeadlineExceeded) {
			p.logger.Error(
				"postgres query timeout",
				zap.String("operation", "get user by email"),
				zap.Duration("timeout", 5*time.Second),
				zap.Error(err),
			)

			return nil, &domain.AppError{
				Code:    "ErrTimeout",
				Message: "database query timed out",
				Status:  http.StatusGatewayTimeout,
				Cause:   err,
			}
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			p.logger.Error(
				"postgres query failed",
				zap.String("operation", "get user by email"),
				zap.String("code", string(pgErr.Code)),
				zap.String("constraint", pgErr.ConstraintName),
				zap.Error(err),
			)

			return nil, domain.NewErrInternal(err)
		}

		p.logger.Error(
			"postgres query failed",
			zap.String("operation", "get user by email"),
			zap.Error(err),
		)

		return nil, domain.NewErrInternal(err)
	}

	return user, nil
}
