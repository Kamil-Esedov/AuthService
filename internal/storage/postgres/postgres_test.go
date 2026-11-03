package postgres_test

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/jackc/pgx/v5/pgxpool"
)

var testDB *pgxpool.Pool

func TestMain(m *testing.M) {
	code := run(m)
	os.Exit(code)
}

func run(m *testing.M) int {
	ctx := context.Background()

	container, err := tcpostgres.Run(
		ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("auth_service"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		log.Printf("failed to start containers: %v", err)
		return 1
	}
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			log.Printf("failed to terminate container: %v", err)
		}
	}()

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Printf("failed to get connection string: %v", err)
		return 1
	}

	testDB, err = pgxpool.New(ctx, connStr)
	if err != nil {
		log.Printf("failed to connect to db: %v", err)
		return 1
	}
	defer testDB.Close()

	if err := applyMigrations(ctx, testDB, "../../../migrations"); err != nil {
		log.Printf("failed to apply migrations: %v", err)
		return 1
	}

	return m.Run()
}

func applyMigrations(ctx context.Context, db *pgxpool.Pool, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var upFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") {
			upFiles = append(upFiles, entry.Name())
		}
	}
	sort.Strings(upFiles)

	for _, file := range upFiles {
		path := filepath.Join(dir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}
		if _, err := db.Exec(ctx, string(content)); err != nil {
			return fmt.Errorf("exec migration %s: %w", file, err)
		}
	}

	return nil
}

func truncateTables(t *testing.T) {
	_, err := testDB.Exec(
		context.Background(),
		"TRUNCATE refresh_sessions, users CASCADE",
	)
	if err != nil {
		t.Fatal(err)
	}
}

func mustInsertUser(t *testing.T, u *domain.User) {
	t.Helper()
	_, err := testDB.Exec(
		context.Background(),
		"INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
		u.ID,
		u.Email,
		u.PasswordHash,
		u.Role,
	)
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}
}

func assertAppError(t *testing.T, err error, wantCode string, wantStatus int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q and status %d, got nil", wantCode, wantStatus)
	}

	var appErr *domain.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("error type: got %T (%v), want *domain.AppError", err, err)
	}
	if appErr.Code != wantCode {
		t.Errorf("error code: got %q, want %q", appErr.Code, wantCode)
	}
	if wantStatus != 0 && appErr.Status != wantStatus {
		t.Errorf("error status: got %d, want %d", appErr.Status, wantStatus)
	}
}

func assertUserEqual(t *testing.T, got, want *domain.User) {
	t.Helper()
	if got == nil {
		t.Fatal("got nil user")
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %v, want %v", got.ID, want.ID)
	}
	if !strings.EqualFold(got.Email, want.Email) {
		t.Errorf("Email: got %q, want %q", got.Email, want.Email)
	}
	if got.PasswordHash != want.PasswordHash {
		t.Errorf("PasswordHash: got %q, want %q", got.PasswordHash, want.PasswordHash)
	}
	if got.Role != want.Role {
		t.Errorf("Role: got %q, want %q", got.Role, want.Role)
	}
}

func assertSessionEqual(t *testing.T, got, want *domain.Session) {
	t.Helper()
	if got == nil {
		t.Fatal("got nil session")
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %v, want %v", got.ID, want.ID)
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID: got %v, want %v", got.UserID, want.UserID)
	}
	if got.TokenHash != want.TokenHash {
		t.Errorf("TokenHash: got %q, want %q", got.TokenHash, want.TokenHash)
	}
	if got.UserAgent != want.UserAgent {
		t.Errorf("UserAgent: got %q, want %q", got.UserAgent, want.UserAgent)
	}
	if got.IP != want.IP {
		t.Errorf("IP: got %v, want %v", got.IP, want.IP)
	}
	if difference := got.ExpiresAt.Sub(want.ExpiresAt); difference > time.Microsecond || difference < -time.Microsecond {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}
