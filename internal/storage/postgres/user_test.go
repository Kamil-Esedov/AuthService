package postgres_test

import (
	"auth-service/internal/domain"
	"auth-service/internal/storage/postgres"
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func newCanceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return ctx
}

func TestStoragePostgres_Register(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())

	tests := []struct {
		name          string
		user          *domain.User
		prepare       func(t *testing.T)
		ctx           context.Context
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name: "Успешная регистрация",
			user: &domain.User{
				Email:        "example@example.com",
				PasswordHash: "password-hash",
				Role:         domain.RoleUser,
			},
		},
		{
			name: "Занятый email (независимо от регистра)",
			user: &domain.User{
				Email:        "EXAMPLE@example.com",
				PasswordHash: "another-password-hash",
				Role:         domain.RoleUser,
			},
			prepare: func(t *testing.T) {
				mustInsertUser(t, &domain.User{
					ID:           uuid.New(),
					Email:        "example@example.com",
					PasswordHash: "password-hash",
					Role:         domain.RoleUser,
				})
			},
			wantErrCode:   "ErrEmailTaken",
			wantErrStatus: http.StatusConflict,
		},
		{
			name: "Контекст отменен",
			user: &domain.User{
				Email:        "example@example.com",
				PasswordHash: "password-hash",
				Role:         domain.RoleUser,
			},
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

			id, err := storage.Register(ctx, tt.user)

			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id == uuid.Nil {
				t.Fatal("register returned an empty user ID")
			}
			if tt.user.ID != id {
				t.Errorf("user.ID was not updated in-place: got %v, want %v", tt.user.ID, id)
			}

			savedUser, err := storage.GetByID(context.Background(), id)
			if err != nil {
				t.Fatalf("failed to fetch registered user from DB: %v", err)
			}

			assertUserEqual(t, savedUser, tt.user)
		})
	}
}

func TestStoragePostgres_GetByEmail(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())

	seedUser := func(t *testing.T) *domain.User {
		t.Helper()
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "example@example.com",
			PasswordHash: "password-hash",
			Role:         domain.RoleUser,
		}
		mustInsertUser(t, u)
		return u
	}

	tests := []struct {
		name          string
		email         string
		prepare       func(t *testing.T) *domain.User
		ctx           context.Context
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name:    "Пользователь найден (точное совпадение)",
			email:   "example@example.com",
			prepare: seedUser,
		},
		{
			name:    "Пользователь найден (другой регистр email)",
			email:   "EXAMPLE@example.com",
			prepare: seedUser,
		},
		{
			name:        "Пользователь не найден",
			email:       "missing@example.com",
			wantErrCode: "ErrUserNotFound",
		},
		{
			name:          "Контекст отменен",
			email:         "exanple@example.com",
			ctx:           newCanceledContext(),
			wantErrCode:   "ErrContextCanceled",
			wantErrStatus: 499,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateTables(t)

			var wantUser *domain.User
			if tt.prepare != nil {
				wantUser = tt.prepare(t)
			}

			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}

			got, err := storage.GetByEmail(ctx, tt.email)

			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertUserEqual(t, got, wantUser)
		})
	}
}

func TestStoragePostgres_GetByID(t *testing.T) {
	storage := postgres.NewPostgres(testDB, zap.NewNop())
	existingID := uuid.New()

	tests := []struct {
		name          string
		id            uuid.UUID
		ctx           context.Context
		prepare       func(t *testing.T) *domain.User
		wantErrCode   string
		wantErrStatus int
	}{
		{
			name: "Пользователь найден",
			id:   existingID,
			prepare: func(t *testing.T) *domain.User {
				u := &domain.User{
					ID:           existingID,
					Email:        "example@example.com",
					PasswordHash: "password-hash",
					Role:         domain.RoleUser,
				}
				mustInsertUser(t, u)
				return u
			},
		},
		{
			name:          "Пользователь не найден (нулевой UUID)",
			id:            uuid.Nil,
			wantErrCode:   "ErrUserNotFound",
			wantErrStatus: http.StatusNotFound,
		},
		{
			name:          "Пользователь не найден (несуществующий ID)",
			id:            uuid.New(),
			wantErrCode:   "ErrUserNotFound",
			wantErrStatus: http.StatusNotFound,
		},
		{
			name:          "Контекст отменен",
			id:            existingID,
			ctx:           newCanceledContext(),
			wantErrCode:   "ErrContextCanceled",
			wantErrStatus: 499,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateTables(t)

			var wantUser *domain.User
			if tt.prepare != nil {
				wantUser = tt.prepare(t)
			}

			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}

			got, err := storage.GetByID(ctx, tt.id)

			if tt.wantErrCode != "" {
				assertAppError(t, err, tt.wantErrCode, tt.wantErrStatus)
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertUserEqual(t, got, wantUser)
		})
	}
}
