package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type Postgres struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

func NewPostgres(db *pgxpool.Pool, logger *zap.Logger) *Postgres {
	return &Postgres{
		db:     db,
		logger: logger,
	}
}

func (p *Postgres) handleError(op string, err error) error {
	if errors.Is(err, context.Canceled) {
		return &domain.AppError{
			Code:    "ErrContextCanceled",
			Message: "context canceled by client",
			Status:  499,
			Cause:   err,
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		p.logger.Error("postgres query timeout",
			zap.String("operation", op),
			zap.Duration("timeout", queryTimeout),
			zap.Error(err),
		)
		return &domain.AppError{
			Code:    "ErrTimeout",
			Message: "database query timed out",
			Status:  http.StatusGatewayTimeout,
			Cause:   err,
		}
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		p.logger.Error("postgres query failed",
			zap.String("operation", op),
			zap.String("code", pgErr.Code),
			zap.String("constraint", pgErr.ConstraintName),
			zap.Error(err),
		)
		return domain.NewErrInternal(err)
	}

	p.logger.Error("unexpected postgres error",
		zap.String("operation", op),
		zap.Error(err),
	)
	return domain.NewErrInternal(err)
}
