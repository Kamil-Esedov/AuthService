package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (p *Postgres) CreateSession(ctx context.Context, session *domain.Session) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO refresh_sessions (id, user_id, token_hash, user_agent, ip, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6);
	`

	_, err := p.db.Exec(
		ctxTimeout,
		query,
		session.ID,
		session.UserID,
		session.TokenHash,
		session.UserAgent,
		session.IP,
		session.ExpiresAt,
	)
	if err != nil {
		return p.handleError("create session", err)
	}

	return nil
}

func (p *Postgres) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, user_id, token_hash, user_agent, ip, expires_at, created_at
		FROM refresh_sessions 
		WHERE token_hash = $1;
	`
	var session domain.Session
	if err := p.db.QueryRow(
		ctxTimeout,
		query,
		tokenHash,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.UserAgent,
		&session.IP,
		&session.ExpiresAt,
		&session.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &domain.AppError{
				Code:    "ErrUnauthorized",
				Message: "invalid or expired refresh session",
				Status:  http.StatusUnauthorized,
				Cause:   err,
			}
		}

		return nil, p.handleError("get session by token hash", err)
	}

	return &session, nil
}

func (p *Postgres) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		DELETE FROM refresh_sessions WHERE id = $1;
	`

	cmdTag, err := p.db.Exec(ctxTimeout, query, sessionID)
	if err != nil {
		return p.handleError("delete session", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return &domain.AppError{
			Code:    "ErrSessionNotFound",
			Message: "session not found or already deleted",
			Status:  http.StatusNotFound,
		}
	}

	return nil
}

func (p *Postgres) RotateSession(ctx context.Context, oldSession uuid.UUID, newSession *domain.Session) error {
	txCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := p.db.Begin(txCtx)
	if err != nil {
		return p.handleError("begin session rotation", err)
	}
	defer tx.Rollback(txCtx)

	deleteQuery := `
		DELETE FROM refresh_sessions
		WHERE id = $1 AND expires_at > NOW();
	`

	deleteTag, err := tx.Exec(txCtx, deleteQuery, oldSession)
	if err != nil {
		return p.handleError("delete old session", err)
	}

	if deleteTag.RowsAffected() != 1 {
		return &domain.AppError{
			Code:    "ErrUnauthorized",
			Message: "refresh session is expired or already rotated",
			Status:  http.StatusUnauthorized,
		}
	}

	createQuery := `
		INSERT INTO refresh_sessions
			(id, user_id, token_hash, user_agent, ip, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6);
	`

	_, err = tx.Exec(
		txCtx,
		createQuery,
		newSession.ID,
		newSession.UserID,
		newSession.TokenHash,
		newSession.UserAgent,
		newSession.IP,
		newSession.ExpiresAt,
	)
	if err != nil {
		return p.handleError("create new session", err)
	}

	if err := tx.Commit(txCtx); err != nil {
		return p.handleError("commit session rotation", err)
	}

	return nil
}
