package service_test

import (
	"auth-service/internal/domain"
	"auth-service/internal/service"
	"auth-service/pkg/jwt"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type MockPostgres struct {
	RegisterFunc              func(ctx context.Context, user *domain.User) (uuid.UUID, error)
	GetByEmailFunc            func(ctx context.Context, email string) (*domain.User, error)
	GetByIDFunc               func(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	CreateSessionFunc         func(ctx context.Context, session *domain.Session) error
	GetSessionByTokenHashFunc func(ctx context.Context, tokenHash string) (*domain.Session, error)
	DeleteSessionFunc         func(ctx context.Context, sessionID uuid.UUID) error
	RotateSessionFunc         func(ctx context.Context, oldSession uuid.UUID, newSession *domain.Session) error
}

func (m *MockPostgres) Register(ctx context.Context, user *domain.User) (uuid.UUID, error) {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(ctx, user)
	}
	return uuid.Nil, nil
}

func (m *MockPostgres) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.GetByEmailFunc != nil {
		return m.GetByEmailFunc(ctx, email)
	}
	return nil, nil
}

func (m *MockPostgres) GetByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, userID)
	}
	return nil, nil
}

func (m *MockPostgres) CreateSession(ctx context.Context, session *domain.Session) error {
	if m.CreateSessionFunc != nil {
		return m.CreateSessionFunc(ctx, session)
	}
	return nil
}

func (m *MockPostgres) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	if m.GetSessionByTokenHashFunc != nil {
		return m.GetSessionByTokenHashFunc(ctx, tokenHash)
	}
	return nil, nil
}

func (m *MockPostgres) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	if m.DeleteSessionFunc != nil {
		return m.DeleteSessionFunc(ctx, sessionID)
	}
	return nil
}

func (m *MockPostgres) RotateSession(ctx context.Context, oldSession uuid.UUID, newSession *domain.Session) error {
	if m.RotateSessionFunc != nil {
		return m.RotateSessionFunc(ctx, oldSession, newSession)
	}
	return nil
}

type MockPasswordHasher struct {
	HashFunc    func(password string) (string, error)
	CompareFunc func(password, hash string) bool
}

func (m *MockPasswordHasher) Hash(password string) (string, error) {
	if m.HashFunc != nil {
		return m.HashFunc(password)
	}
	return "", nil
}

func (m *MockPasswordHasher) Compare(password, hash string) bool {
	if m.CompareFunc != nil {
		return m.CompareFunc(password, hash)
	}
	return false
}

type MockTokenManager struct {
	NewAccessTokenFunc  func(userID, role string, ttl time.Duration) (string, error)
	ParseFunc           func(accessToken string) (*jwt.CustomClaims, error)
	NewRefreshTokenFunc func() (string, error)
}

func (m *MockTokenManager) NewAccessToken(userID, role string, ttl time.Duration) (string, error) {
	if m.NewAccessTokenFunc != nil {
		return m.NewAccessTokenFunc(userID, role, ttl)
	}
	return "", nil
}

func (m *MockTokenManager) Parse(accessToken string) (*jwt.CustomClaims, error) {
	if m.ParseFunc != nil {
		return m.ParseFunc(accessToken)
	}
	return nil, nil
}

func (m *MockTokenManager) NewRefreshToken() (string, error) {
	if m.NewRefreshTokenFunc != nil {
		return m.NewRefreshTokenFunc()
	}
	return "", nil
}

func TestAuthService_Register(t *testing.T) {
	expectedID := uuid.New()
	hashErr := errors.New("failed to hash password")
	storageErr := errors.New("failed to register user")

	type testCase struct {
		name                string
		data                domain.RegisterInput
		setupPasswordHasher func(m *MockPasswordHasher)
		setupPostgres       func(m *MockPostgres)
		wantID              uuid.UUID
		wantErr             error
		wantErrCode         string
		wantErrStatus       int
		wantPostgresCalls   int
	}

	tests := []testCase{
		{
			name: "Успешная регистрация",
			data: domain.RegisterInput{
				Email:    "example@example.com",
				Password: "password123",
			},
			setupPasswordHasher: func(m *MockPasswordHasher) {
				m.HashFunc = func(password string) (string, error) {
					return "passwordHash", nil
				}
			},
			setupPostgres: func(m *MockPostgres) {
				m.RegisterFunc = func(ctx context.Context, user *domain.User) (uuid.UUID, error) {
					if user.Email != "example@example.com" {
						t.Errorf("expected email %q, got %q", "example@example.com", user.Email)
					}
					if user.PasswordHash != "passwordHash" {
						t.Errorf("expected password hash %q, got %q", "passwordHash", user.PasswordHash)
					}
					if user.Role != domain.RoleUser {
						t.Errorf("expected role %q, got %q", domain.RoleUser, user.Role)
					}
					return expectedID, nil
				}
			},
			wantID:            expectedID,
			wantPostgresCalls: 1,
		},
		{
			name: "Ошибка хеширования пароля",
			data: domain.RegisterInput{
				Email:    "example@example.com",
				Password: "password123",
			},
			setupPasswordHasher: func(m *MockPasswordHasher) {
				m.HashFunc = func(password string) (string, error) {
					return "", hashErr
				}
			},
			wantErr:           hashErr,
			wantErrCode:       "ErrInternalServer",
			wantErrStatus:     http.StatusInternalServerError,
			wantPostgresCalls: 0,
		},
		{
			name: "Ошибка регистрации в хранилище",
			data: domain.RegisterInput{
				Email:    "example@example.com",
				Password: "password123",
			},
			setupPasswordHasher: func(m *MockPasswordHasher) {
				m.HashFunc = func(password string) (string, error) {
					return "passwordHash", nil
				}
			},
			setupPostgres: func(m *MockPostgres) {
				m.RegisterFunc = func(ctx context.Context, user *domain.User) (uuid.UUID, error) {
					return uuid.Nil, storageErr
				}
			},
			wantErr:           storageErr,
			wantPostgresCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			passwordHasher := &MockPasswordHasher{}
			if tc.setupPasswordHasher != nil {
				tc.setupPasswordHasher(passwordHasher)
			}

			postgres := &MockPostgres{}
			postgresCalls := 0
			if tc.setupPostgres != nil {
				tc.setupPostgres(postgres)
			}
			register := postgres.RegisterFunc
			postgres.RegisterFunc = func(ctx context.Context, user *domain.User) (uuid.UUID, error) {
				postgresCalls++
				return register(ctx, user)
			}

			tokenManager := &MockTokenManager{}

			authService := service.NewAuthService(
				tokenManager,
				15*time.Minute,
				7*24*time.Hour,
				postgres,
				passwordHasher,
				zap.NewNop(),
			)

			got, err := authService.Register(context.Background(), tc.data)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
			}

			if tc.wantErrCode != "" {
				var appErr *domain.AppError
				if !errors.As(err, &appErr) {
					t.Fatalf("expected AppError, got %T: %v", err, err)
				}
				if appErr.Code != tc.wantErrCode {
					t.Errorf("expected error code %q, got %q", tc.wantErrCode, appErr.Code)
				}
				if appErr.Status != tc.wantErrStatus {
					t.Errorf("expected error status %d, got %d", tc.wantErrStatus, appErr.Status)
				}
			} else if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantID {
					t.Errorf("expected user ID %s, got %s", tc.wantID, got)
				}
			}

			if postgresCalls != tc.wantPostgresCalls {
				t.Errorf("expected %d postgres calls, got %d", tc.wantPostgresCalls, postgresCalls)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	expectedUser := &domain.User{
		ID:           uuid.New(),
		Email:        "example@example.com",
		PasswordHash: "password-hash",
		Role:         domain.RoleUser,
	}
	expectedTokens := &domain.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
	getByEmailErr := errors.New("failed to get user by email")
	issueTokensErr := errors.New("failed to issue tokens")
	storageErr := errors.New("failed to create session")

	type testCase struct {
		name                   string
		data                   domain.LoginInput
		setupPostgres          func(m *MockPostgres)
		setupHasher            func(m *MockPasswordHasher)
		setupTokenManager      func(m *MockTokenManager)
		wantTokens             *domain.TokenPair
		wantErr                error
		wantErrCode            string
		wantErrStatus          int
		wantGetByEmailCalls    int
		wantCreateSessionCalls int
	}

	tests := []testCase{
		{
			name: "Успешная авторизация",
			data: domain.LoginInput{Email: expectedUser.Email, Password: "password123", UserAgent: "test-agent", IP: "127.0.0.1"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					if email != expectedUser.Email {
						t.Errorf("expected email %q, got %q", expectedUser.Email, email)
					}
					return expectedUser, nil
				}
				m.CreateSessionFunc = func(ctx context.Context, session *domain.Session) error {
					if session.UserID != expectedUser.ID || session.UserAgent != "test-agent" || session.IP.String() != "127.0.0.1" {
						t.Errorf("unexpected session: %+v", session)
					}
					return nil
				}
			},
			setupHasher: func(m *MockPasswordHasher) {
				m.CompareFunc = func(password, hash string) bool {
					return password == "password123" && hash == expectedUser.PasswordHash
				}
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) {
					if userID != expectedUser.ID.String() || role != string(expectedUser.Role) || ttl != 15*time.Minute {
						t.Errorf("unexpected access token arguments: %q, %q, %s", userID, role, ttl)
					}
					return expectedTokens.AccessToken, nil
				}
				m.NewRefreshTokenFunc = func() (string, error) { return expectedTokens.RefreshToken, nil }
			},
			wantTokens:             expectedTokens,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 1,
		},
		{
			name: "Пользователь не найден",
			data: domain.LoginInput{Email: "unknown@example.com", Password: "password123"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, &domain.AppError{Code: "ErrUserNotFound", Message: "user not found", Status: http.StatusNotFound}
				}
			},
			wantErrCode:            "ErrUnauthorized",
			wantErrStatus:          http.StatusUnauthorized,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 0,
		},
		{
			name: "Ошибка поиска пользователя",
			data: domain.LoginInput{Email: expectedUser.Email, Password: "password123"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, getByEmailErr
				}
			},
			wantErr:                getByEmailErr,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 0,
		},
		{
			name: "Неверный пароль",
			data: domain.LoginInput{Email: expectedUser.Email, Password: "wrong-password"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) { return expectedUser, nil }
			},
			setupHasher: func(m *MockPasswordHasher) {
				m.CompareFunc = func(password, hash string) bool { return false }
			},
			wantErrCode:            "ErrUnauthorized",
			wantErrStatus:          http.StatusUnauthorized,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 0,
		},
		{
			name: "Заблокированный пользователь",
			data: domain.LoginInput{Email: expectedUser.Email, Password: "password123"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					blockedUser := *expectedUser
					blockedUser.IsBlocked = true
					return &blockedUser, nil
				}
			},
			setupHasher: func(m *MockPasswordHasher) {
				m.CompareFunc = func(password, hash string) bool { return true }
			},
			wantErrCode:            "ErrForbidden",
			wantErrStatus:          http.StatusForbidden,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 0,
		},
		{
			name: "Ошибка создания сессии",
			data: domain.LoginInput{Email: expectedUser.Email, Password: "password123"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) { return expectedUser, nil }
				m.CreateSessionFunc = func(ctx context.Context, session *domain.Session) error { return storageErr }
			},
			setupHasher: func(m *MockPasswordHasher) {
				m.CompareFunc = func(password, hash string) bool { return true }
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) { return expectedTokens.AccessToken, nil }
				m.NewRefreshTokenFunc = func() (string, error) { return expectedTokens.RefreshToken, nil }
			},
			wantErr:                storageErr,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 1,
		},
		{
			name: "Ошибка выпуска токенов",
			data: domain.LoginInput{Email: expectedUser.Email, Password: "password123", IP: "127.0.0.1"},
			setupPostgres: func(m *MockPostgres) {
				m.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return expectedUser, nil
				}
			},
			setupHasher: func(m *MockPasswordHasher) {
				m.CompareFunc = func(password, hash string) bool { return true }
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) {
					return "", issueTokensErr
				}
			},
			wantErr:                issueTokensErr,
			wantGetByEmailCalls:    1,
			wantCreateSessionCalls: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			postgres := &MockPostgres{}
			if tc.setupPostgres != nil {
				tc.setupPostgres(postgres)
			}
			getByEmailCalls := 0
			getByEmail := postgres.GetByEmailFunc
			postgres.GetByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
				getByEmailCalls++
				return getByEmail(ctx, email)
			}
			createSessionCalls := 0
			createSession := postgres.CreateSessionFunc
			if createSession == nil {
				createSession = func(ctx context.Context, session *domain.Session) error { return nil }
			}
			postgres.CreateSessionFunc = func(ctx context.Context, session *domain.Session) error {
				createSessionCalls++
				return createSession(ctx, session)
			}

			passwordHasher := &MockPasswordHasher{}
			if tc.setupHasher != nil {
				tc.setupHasher(passwordHasher)
			}
			tokenManager := &MockTokenManager{}
			if tc.setupTokenManager != nil {
				tc.setupTokenManager(tokenManager)
			}

			authService := service.NewAuthService(tokenManager, 15*time.Minute, 7*24*time.Hour, postgres, passwordHasher, zap.NewNop())
			got, err := authService.Login(context.Background(), tc.data)

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantErrCode != "" {
				var appErr *domain.AppError
				if !errors.As(err, &appErr) {
					t.Fatalf("expected AppError, got %T: %v", err, err)
				}
				if appErr.Code != tc.wantErrCode || appErr.Status != tc.wantErrStatus {
					t.Errorf("expected %s/%d, got %s/%d", tc.wantErrCode, tc.wantErrStatus, appErr.Code, appErr.Status)
				}
			}
			if tc.wantTokens != nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if *got != *tc.wantTokens {
					t.Errorf("expected tokens %+v, got %+v", *tc.wantTokens, *got)
				}
			}
			if getByEmailCalls != tc.wantGetByEmailCalls {
				t.Errorf("expected %d GetByEmail calls, got %d", tc.wantGetByEmailCalls, getByEmailCalls)
			}
			if createSessionCalls != tc.wantCreateSessionCalls {
				t.Errorf("expected %d CreateSession calls, got %d", tc.wantCreateSessionCalls, createSessionCalls)
			}
		})
	}
}

func TestAuthService_Refresh(t *testing.T) {
	expectedUser := &domain.User{ID: uuid.New(), Role: domain.RoleUser}
	oldSession := &domain.Session{
		ID:        uuid.New(),
		UserID:    expectedUser.ID,
		IP:        netip.MustParseAddr("192.0.2.10"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	expectedTokens := &domain.TokenPair{AccessToken: "new-access-token", RefreshToken: "new-refresh-token"}
	sessionErr := errors.New("failed to get session")
	userErr := errors.New("failed to get user")
	rotateErr := errors.New("failed to rotate session")
	accessTokenErr := errors.New("failed to create access token")
	refreshTokenErr := errors.New("failed to create refresh token")

	type testCase struct {
		name                            string
		refreshToken                    string
		userAgent                       string
		rawID                           string
		setupPostgres                   func(m *MockPostgres)
		wantTokens                      *domain.TokenPair
		wantErr                         error
		wantErrCode                     string
		wantErrStatus                   int
		wantGetSessionsByTokenHashCalls int
		wantGetByIDCalls                int
		wantRotateSessionCalls          int
		setupTokenManager               func(m *MockTokenManager)
	}

	tests := []testCase{
		{
			name: "Успешное обновление токенов", refreshToken: "old-refresh-token", userAgent: "new-agent", rawID: "198.51.100.20",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) {
					if tokenHash == "" {
						t.Error("expected non-empty refresh token hash")
					}
					return oldSession, nil
				}
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
					if userID != expectedUser.ID {
						t.Errorf("expected user ID %s, got %s", expectedUser.ID, userID)
					}
					return expectedUser, nil
				}
				m.RotateSessionFunc = func(ctx context.Context, sessionID uuid.UUID, session *domain.Session) error {
					if sessionID != oldSession.ID {
						t.Errorf("expected old session ID %s, got %s", oldSession.ID, sessionID)
					}
					if session.UserID != expectedUser.ID || session.UserAgent != "new-agent" || session.IP.String() != "198.51.100.20" {
						t.Errorf("unexpected rotated session: %+v", session)
					}
					return nil
				}
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) {
					if userID != expectedUser.ID.String() || role != string(expectedUser.Role) || ttl != 15*time.Minute {
						t.Errorf("unexpected access token arguments: %q, %q, %s", userID, role, ttl)
					}
					return expectedTokens.AccessToken, nil
				}
				m.NewRefreshTokenFunc = func() (string, error) { return expectedTokens.RefreshToken, nil }
			},
			wantTokens: expectedTokens, wantGetSessionsByTokenHashCalls: 1, wantGetByIDCalls: 1, wantRotateSessionCalls: 1,
		},
		{
			name: "Ошибка поиска сессии", refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return nil, sessionErr }
			},
			wantErr: sessionErr, wantGetSessionsByTokenHashCalls: 1,
		},
		{
			name: "Истёкшая сессия", refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				expiredSession := *oldSession
				expiredSession.ExpiresAt = time.Now().Add(-time.Minute)
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return &expiredSession, nil }
			},
			wantErrCode: "ErrUnauthorized", wantErrStatus: http.StatusUnauthorized, wantGetSessionsByTokenHashCalls: 1,
		},
		{
			name: "Ошибка поиска пользователя", refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return oldSession, nil }
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return nil, userErr }
			},
			wantErr: userErr, wantGetSessionsByTokenHashCalls: 1, wantGetByIDCalls: 1,
		},
		{
			name: "Заблокированный пользователь", refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				blockedUser := *expectedUser
				blockedUser.IsBlocked = true
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return oldSession, nil }
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return &blockedUser, nil }
			},
			wantErrCode: "ErrForbidden", wantErrStatus: http.StatusForbidden, wantGetSessionsByTokenHashCalls: 1, wantGetByIDCalls: 1,
		},
		{
			name: "Ошибка генерации access токена", refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return oldSession, nil }
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return expectedUser, nil }
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) { return "", accessTokenErr }
			},
			wantErrCode: "ErrInternalServer", wantErrStatus: http.StatusInternalServerError, wantGetSessionsByTokenHashCalls: 1, wantGetByIDCalls: 1,
		},
		{
			name: "Ошибка генерации refresh токена", refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return oldSession, nil }
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return expectedUser, nil }
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) { return expectedTokens.AccessToken, nil }
				m.NewRefreshTokenFunc = func() (string, error) { return "", refreshTokenErr }
			},
			wantErrCode: "ErrInternalServer", wantErrStatus: http.StatusInternalServerError, wantGetSessionsByTokenHashCalls: 1, wantGetByIDCalls: 1,
		},
		{
			name: "Ошибка ротации сессии", refreshToken: "refresh-token", rawID: "invalid-ip",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) { return oldSession, nil }
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return expectedUser, nil }
				m.RotateSessionFunc = func(ctx context.Context, sessionID uuid.UUID, session *domain.Session) error {
					if session.IP != oldSession.IP {
						t.Errorf("expected old session IP %s, got %s", oldSession.IP, session.IP)
					}
					return rotateErr
				}
			},
			setupTokenManager: func(m *MockTokenManager) {
				m.NewAccessTokenFunc = func(userID, role string, ttl time.Duration) (string, error) { return expectedTokens.AccessToken, nil }
				m.NewRefreshTokenFunc = func() (string, error) { return expectedTokens.RefreshToken, nil }
			},
			wantErr: rotateErr, wantGetSessionsByTokenHashCalls: 1, wantGetByIDCalls: 1, wantRotateSessionCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			postgres := &MockPostgres{}
			if tc.setupPostgres != nil {
				tc.setupPostgres(postgres)
			}

			getSessionCalls := 0
			getSession := postgres.GetSessionByTokenHashFunc
			postgres.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) {
				getSessionCalls++
				return getSession(ctx, tokenHash)
			}

			getByIDCalls := 0
			getByID := postgres.GetByIDFunc
			if getByID == nil {
				getByID = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return nil, nil }
			}

			postgres.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
				getByIDCalls++
				return getByID(ctx, userID)
			}

			rotateCalls := 0
			rotate := postgres.RotateSessionFunc
			if rotate == nil {
				rotate = func(ctx context.Context, sessionID uuid.UUID, session *domain.Session) error { return nil }
			}

			postgres.RotateSessionFunc = func(ctx context.Context, sessionID uuid.UUID, session *domain.Session) error {
				rotateCalls++
				return rotate(ctx, sessionID, session)
			}

			tokenManager := &MockTokenManager{}
			if tc.setupTokenManager != nil {
				tc.setupTokenManager(tokenManager)
			}

			authService := service.NewAuthService(tokenManager, 15*time.Minute, 7*24*time.Hour, postgres, &MockPasswordHasher{}, zap.NewNop())
			got, err := authService.Refresh(context.Background(), tc.refreshToken, tc.userAgent, tc.rawID)

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}

			if tc.wantErrCode != "" {
				var appErr *domain.AppError
				if !errors.As(err, &appErr) {
					t.Fatalf("expected AppError, got %T: %v", err, err)
				}

				if appErr.Code != tc.wantErrCode || appErr.Status != tc.wantErrStatus {
					t.Errorf("expected %s/%d, got %s/%d", tc.wantErrCode, tc.wantErrStatus, appErr.Code, appErr.Status)
				}
			}

			if tc.wantTokens != nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if *got != *tc.wantTokens {
					t.Errorf("expected tokens %+v, got %+v", *tc.wantTokens, *got)
				}
			}

			if getSessionCalls != tc.wantGetSessionsByTokenHashCalls {
				t.Errorf("expected %d GetSessionByTokenHash calls, got %d", tc.wantGetSessionsByTokenHashCalls, getSessionCalls)
			}

			if getByIDCalls != tc.wantGetByIDCalls {
				t.Errorf("expected %d GetByID calls, got %d", tc.wantGetByIDCalls, getByIDCalls)
			}

			if rotateCalls != tc.wantRotateSessionCalls {
				t.Errorf("expected %d RotateSession calls, got %d", tc.wantRotateSessionCalls, rotateCalls)
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	sessionErr := errors.New("failed to get session")
	deleteErr := errors.New("failed to delete session")
	session := &domain.Session{
		ID: uuid.New(),
	}

	type testCase struct {
		name                            string
		refreshToken                    string
		setupPostgres                   func(m *MockPostgres)
		wantErr                         error
		wantErrCode                     string
		wantErrStatus                   int
		wantGetSessionsByTokenHashCalls int
		wantDeleteSessionCalls          int
	}

	tests := []testCase{
		{
			name:         "Успешное удаление сессии",
			refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) {
					expectedHash := sha256.Sum256([]byte("refresh-token"))
					if tokenHash != hex.EncodeToString(expectedHash[:]) {
						t.Errorf("expected token hash %q, got %q", hex.EncodeToString(expectedHash[:]), tokenHash)
					}
					return session, nil
				}
				m.DeleteSessionFunc = func(ctx context.Context, sessionID uuid.UUID) error {
					if sessionID != session.ID {
						t.Errorf("expected session ID %s, got %s", session.ID, sessionID)
					}
					return nil
				}
			},
			wantGetSessionsByTokenHashCalls: 1,
			wantDeleteSessionCalls:          1,
		},
		{
			name:         "Ошибка поиска сессии",
			refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) {
					return nil, sessionErr
				}
			},
			wantErr:                         sessionErr,
			wantGetSessionsByTokenHashCalls: 1,
		},
		{
			name:         "Ошибка удаления сессии",
			refreshToken: "refresh-token",
			setupPostgres: func(m *MockPostgres) {
				m.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) {
					return session, nil
				}
				m.DeleteSessionFunc = func(ctx context.Context, sessionID uuid.UUID) error {
					return deleteErr
				}
			},
			wantErr:                         deleteErr,
			wantGetSessionsByTokenHashCalls: 1,
			wantDeleteSessionCalls:          1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			postgres := &MockPostgres{}
			if tc.setupPostgres != nil {
				tc.setupPostgres(postgres)
			}

			getSessionCalls := 0
			getSession := postgres.GetSessionByTokenHashFunc
			postgres.GetSessionByTokenHashFunc = func(ctx context.Context, tokenHash string) (*domain.Session, error) {
				getSessionCalls++
				return getSession(ctx, tokenHash)
			}
			deleteSessionCalls := 0
			deleteSession := postgres.DeleteSessionFunc
			if deleteSession == nil {
				deleteSession = func(ctx context.Context, sessionID uuid.UUID) error { return nil }
			}
			postgres.DeleteSessionFunc = func(ctx context.Context, sessionID uuid.UUID) error {
				deleteSessionCalls++
				return deleteSession(ctx, sessionID)
			}

			authService := service.NewAuthService(
				&MockTokenManager{},
				15*time.Minute,
				7*24*time.Hour,
				postgres,
				&MockPasswordHasher{},
				zap.NewNop(),
			)
			err := authService.Logout(context.Background(), tc.refreshToken)

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if getSessionCalls != tc.wantGetSessionsByTokenHashCalls {
				t.Errorf("expected %d GetSessionByTokenHash calls, got %d", tc.wantGetSessionsByTokenHashCalls, getSessionCalls)
			}
			if deleteSessionCalls != tc.wantDeleteSessionCalls {
				t.Errorf("expected %d DeleteSession calls, got %d", tc.wantDeleteSessionCalls, deleteSessionCalls)
			}
		})
	}
}

func TestAuthService_GetMe(t *testing.T) {
	uID := uuid.New()
	user := &domain.User{
		ID:    uID,
		Email: "example@example.com",
		Role:  domain.RoleUser,
	}
	storageErr := errors.New("failed to get user")

	type testCase struct {
		name             string
		userID           uuid.UUID
		setupPostgres    func(m *MockPostgres)
		wantErr          error
		wantErrCode      string
		wantErrStatus    int
		wantGetByIDCalls int
	}

	tests := []testCase{
		{
			name:   "Успешно получены данные",
			userID: uID,
			setupPostgres: func(m *MockPostgres) {
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) { return user, nil }
			},
			wantErr:          nil,
			wantGetByIDCalls: 1,
		},
		{
			name:   "Ошибка получения данных",
			userID: uID,
			setupPostgres: func(m *MockPostgres) {
				m.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
					return nil, storageErr
				}
			},
			wantErr:          storageErr,
			wantGetByIDCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			postgres := &MockPostgres{}
			if tc.setupPostgres != nil {
				tc.setupPostgres(postgres)
			}

			getByIDCalls := 0
			getByID := postgres.GetByIDFunc
			postgres.GetByIDFunc = func(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
				getByIDCalls++
				if userID != tc.userID {
					t.Errorf("expected user ID %s, got %s", tc.userID, userID)
				}
				return getByID(ctx, userID)
			}

			authService := service.NewAuthService(
				&MockTokenManager{},
				15*time.Minute,
				7*24*time.Hour,
				postgres,
				&MockPasswordHasher{},
				zap.NewNop(),
			)
			got, err := authService.GetMe(context.Background(), tc.userID)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != user {
					t.Errorf("expected user pointer %p, got %p", user, got)
				}
			}

			if getByIDCalls != tc.wantGetByIDCalls {
				t.Errorf("expected %d GetByID calls, got %d", tc.wantGetByIDCalls, getByIDCalls)
			}
		})
	}
}

func TestAuthService_ParseToken(t *testing.T) {
	expectedClaims := &jwt.CustomClaims{
		UserID: "user-id",
		Role:   string(domain.RoleUser),
	}
	parseErr := errors.New("failed to parse token")

	type testCase struct {
		name                string
		accessToken         string
		setupTokenManager   func(m *MockTokenManager)
		wantClaims          *jwt.CustomClaims
		wantErr             error
		wantErrCode         string
		wantErrStatus       int
		wantParseTokenCalls int
	}

	tests := []testCase{
		{
			name:        "Успешный разбор токена",
			accessToken: "valid-access-token",
			setupTokenManager: func(m *MockTokenManager) {
				m.ParseFunc = func(accessToken string) (*jwt.CustomClaims, error) {
					if accessToken != "valid-access-token" {
						t.Errorf("expected access token %q, got %q", "valid-access-token", accessToken)
					}
					return expectedClaims, nil
				}
			},
			wantClaims:          expectedClaims,
			wantParseTokenCalls: 1,
		},
		{
			name:        "Истёкший токен",
			accessToken: "expired-access-token",
			setupTokenManager: func(m *MockTokenManager) {
				m.ParseFunc = func(accessToken string) (*jwt.CustomClaims, error) {
					return nil, jwt.ErrExpiredToken
				}
			},
			wantErr:             jwt.ErrExpiredToken,
			wantErrCode:         "ErrTokenExpired",
			wantErrStatus:       http.StatusUnauthorized,
			wantParseTokenCalls: 1,
		},
		{
			name:        "Невалидный токен",
			accessToken: "invalid-access-token",
			setupTokenManager: func(m *MockTokenManager) {
				m.ParseFunc = func(accessToken string) (*jwt.CustomClaims, error) {
					return nil, parseErr
				}
			},
			wantErr:             parseErr,
			wantErrCode:         "ErrUnauthorized",
			wantErrStatus:       http.StatusUnauthorized,
			wantParseTokenCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenManager := &MockTokenManager{}
			if tc.setupTokenManager != nil {
				tc.setupTokenManager(tokenManager)
			}

			parseCalls := 0
			parse := tokenManager.ParseFunc
			tokenManager.ParseFunc = func(accessToken string) (*jwt.CustomClaims, error) {
				parseCalls++
				return parse(accessToken)
			}

			authService := service.NewAuthService(
				tokenManager,
				15*time.Minute,
				7*24*time.Hour,
				&MockPostgres{},
				&MockPasswordHasher{},
				zap.NewNop(),
			)
			got, err := authService.ParseToken(tc.accessToken)

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantErrCode != "" {
				var appErr *domain.AppError
				if !errors.As(err, &appErr) {
					t.Fatalf("expected AppError, got %T: %v", err, err)
				}
				if appErr.Code != tc.wantErrCode || appErr.Status != tc.wantErrStatus {
					t.Errorf("expected %s/%d, got %s/%d", tc.wantErrCode, tc.wantErrStatus, appErr.Code, appErr.Status)
				}
			}
			if tc.wantClaims != nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantClaims {
					t.Errorf("expected claims pointer %p, got %p", tc.wantClaims, got)
				}
			}
			if parseCalls != tc.wantParseTokenCalls {
				t.Errorf("expected %d Parse calls, got %d", tc.wantParseTokenCalls, parseCalls)
			}
		})
	}
}
