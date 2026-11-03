package postgres_test

import (
	"auth-service/internal/domain"
	"auth-service/internal/storage/postgres"
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestStoragePostgres_CreateSession(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())

	tests := []struct {
		name          string
		session       *domain.Session
		ctx           context.Context
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name: "Успешное создание",
			session: &domain.Session{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				TokenHash: "token-hash",
				UserAgent: "test-agent",
				IP:        netip.MustParseAddr("192.0.2.1"),
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
		{
			name: "Контекст отменен",
			session: &domain.Session{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				TokenHash: "token-hash",
				UserAgent: "test-agent",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			ctx:           newCanceledContext(),
			wantErrCode:   "ErrContextCanceled",
			wantErrStatus: 499,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateTables(t)
			mustInsertUser(t, &domain.User{ID: tt.session.UserID, Email: "example@example.com", PasswordHash: "password-hash", Role: domain.RoleUser})

			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}

			err := storage.CreateSession(ctx, tt.session)
			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, err := storage.GetSessionByTokenHash(context.Background(), tt.session.TokenHash)
			if err != nil {
				t.Fatalf("failed to fetch created session: %v", err)
			}
			assertSessionEqual(t, got, tt.session)
		})
	}
}

func TestStoragePostgres_GetSessionByTokenHash(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())
	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: "token-hash",
		UserAgent: "test-agent",
		IP:        netip.MustParseAddr("192.0.2.1"),
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond),
	}

	tests := []struct {
		name          string
		tokenHash     string
		prepare       bool
		ctx           context.Context
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name:      "Сессия найдена",
			tokenHash: session.TokenHash,
			prepare:   true,
		},
		{
			name:          "Сессия не найдена",
			tokenHash:     "missing-token",
			wantErrCode:   "ErrUnauthorized",
			wantErrStatus: http.StatusUnauthorized,
		},
		{
			name:          "Контекст отменен",
			tokenHash:     session.TokenHash,
			ctx:           newCanceledContext(),
			wantErrCode:   "ErrContextCanceled",
			wantErrStatus: 499,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateTables(t)
			if tt.prepare {
				mustInsertUser(t, &domain.User{ID: session.UserID, Email: "example@example.com", PasswordHash: "password-hash", Role: domain.RoleUser})
				if err := storage.CreateSession(context.Background(), session); err != nil {
					t.Fatalf("failed to create test session: %v", err)
				}
			}

			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			got, err := storage.GetSessionByTokenHash(ctx, tt.tokenHash)
			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertSessionEqual(t, got, session)
		})
	}
}

func TestStoragePostgres_DeleteSession(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())
	session := &domain.Session{ID: uuid.New(), UserID: uuid.New(), TokenHash: "token-hash", UserAgent: "test-agent", ExpiresAt: time.Now().Add(time.Hour)}

	tests := []struct {
		name          string
		ctx           context.Context
		prepare       bool
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name:    "Успешное удаление",
			prepare: true,
		},
		{
			name:          "Сессия не найдена",
			wantErrCode:   "ErrSessionNotFound",
			wantErrStatus: http.StatusNotFound,
		},
		{
			name:          "Контекст отменен",
			prepare:       true,
			ctx:           newCanceledContext(),
			wantErrCode:   "ErrContextCanceled",
			wantErrStatus: 499,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateTables(t)
			if tt.prepare {
				mustInsertUser(t, &domain.User{ID: session.UserID, Email: "example@example.com", PasswordHash: "password-hash", Role: domain.RoleUser})
				if err := storage.CreateSession(context.Background(), session); err != nil {
					t.Fatalf("failed to create test session: %v", err)
				}
			}

			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			err := storage.DeleteSession(ctx, session.ID)
			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_, err = storage.GetSessionByTokenHash(context.Background(), session.TokenHash)
			assertAppError(t, err, "ErrUnauthorized", http.StatusUnauthorized)
		})
	}
}

func TestStoragePostgres_RotateSession(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())
	oldSession := &domain.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: "old-token",
		UserAgent: "old-agent",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	newSession := &domain.Session{
		ID:        uuid.New(),
		UserID:    oldSession.UserID,
		TokenHash: "new-token",
		UserAgent: "new-agent",
		IP:        netip.MustParseAddr("192.0.2.2"),
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}

	tests := []struct {
		name          string
		prepare       func(t *testing.T)
		ctx           context.Context
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name: "Успешная ротация",
			prepare: func(t *testing.T) {
				mustInsertUser(t, &domain.User{ID: oldSession.UserID, Email: "example@example.com", PasswordHash: "password-hash", Role: domain.RoleUser})
				if err := storage.CreateSession(context.Background(), oldSession); err != nil {
					t.Fatalf("failed to create old session: %v", err)
				}
			},
		},
		{
			name:          "Старая сессия не найдена",
			wantErrCode:   "ErrUnauthorized",
			wantErrStatus: http.StatusUnauthorized,
		},
		{
			name:          "Контекст отменен",
			ctx:           newCanceledContext(),
			wantErrCode:   "ErrContextCanceled",
			wantErrStatus: 499,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateTables(t)
			if tt.prepare != nil {
				tt.prepare(t)
			}
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}

			err := storage.RotateSession(ctx, oldSession.ID, newSession)
			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, err := storage.GetSessionByTokenHash(context.Background(), oldSession.TokenHash); err == nil {
				t.Fatal("old session still exists after rotation")
			}
			got, err := storage.GetSessionByTokenHash(context.Background(), newSession.TokenHash)
			if err != nil {
				t.Fatalf("failed to fetch new session: %v", err)
			}
			assertSessionEqual(t, got, newSession)
		})
	}
}
