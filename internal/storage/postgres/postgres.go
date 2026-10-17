package postgres

import (
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
