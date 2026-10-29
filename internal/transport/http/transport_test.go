package httpTransport_test

import (
	"auth-service/internal/domain"
	httpTransport "auth-service/internal/transport/http"
	"auth-service/pkg/jwt"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type MockAuthService struct {
	RegisterFunc   func(ctx context.Context, data domain.RegisterInput) (uuid.UUID, error)
	LoginFunc      func(ctx context.Context, data domain.LoginInput) (*domain.TokenPair, error)
	RefreshFunc    func(ctx context.Context, refreshToken, userAgent, rawID string) (*domain.TokenPair, error)
	LogoutFunc     func(ctx context.Context, refreshToken string) error
	GetMeFunc      func(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	ParseTokenFunc func(accessToken string) (*jwt.CustomClaims, error)
}

func (m *MockAuthService) Register(ctx context.Context, data domain.RegisterInput) (uuid.UUID, error) {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(ctx, data)
	}
	return uuid.Nil, nil
}

func (m *MockAuthService) Login(ctx context.Context, data domain.LoginInput) (*domain.TokenPair, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, data)
	}
	return nil, nil
}

func (m *MockAuthService) Refresh(ctx context.Context, refreshToken, userAgent, rawID string) (*domain.TokenPair, error) {
	if m.RefreshFunc != nil {
		return m.RefreshFunc(ctx, refreshToken, userAgent, rawID)
	}
	return nil, nil
}

func (m *MockAuthService) Logout(ctx context.Context, refreshToken string) error {
	if m.LogoutFunc != nil {
		return m.LogoutFunc(ctx, refreshToken)
	}
	return nil
}

func (m *MockAuthService) GetMe(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	if m.GetMeFunc != nil {
		return m.GetMeFunc(ctx, userID)
	}
	return nil, nil
}

func (m *MockAuthService) ParseToken(accessToken string) (*jwt.CustomClaims, error) {
	if m.ParseTokenFunc != nil {
		return m.ParseTokenFunc(accessToken)
	}
	return nil, nil
}

func TestTransportHTTP_RegisterUser(t *testing.T) {
	type testCase struct {
		name       string
		body       string
		registerID uuid.UUID
		wantErr    error
		wantStatus int
		wantBody   any
		wantInput  domain.RegisterInput
	}

	userID := uuid.New()
	serviceErr := &domain.AppError{
		Code:    "ErrConflict",
		Message: "user already exists",
		Status:  http.StatusConflict,
	}

	tests := []testCase{
		{
			name:       "Успшеная регистрация",
			body:       `{"email":"user@example.com","password":"password123"}`,
			registerID: userID,
			wantStatus: http.StatusCreated,
			wantBody:   httpTransport.RegisterResponseDTO{ID: userID},
			wantInput:  domain.RegisterInput{Email: "user@example.com", Password: "password123"},
		},
		{
			name:       "Невалидный json",
			body:       `{"email":`,
			wantStatus: http.StatusBadRequest,
			wantBody: domain.AppError{
				Code:    "ErrInvalidRequest",
				Message: "invalid json body",
			},
		},
		{
			name:       "Невалидные входные данные",
			body:       `{"email":"not-an-email","password":"short"}`,
			wantStatus: http.StatusBadRequest,
			wantBody: domain.AppError{
				Code:    "ErrValidationFailed",
				Message: "validation failed check input fields",
			},
		},
		{
			name:       "Ошибка на стороне сервиса",
			body:       `{"email":"user@example.com","password":"password123"}`,
			wantErr:    serviceErr,
			wantStatus: http.StatusConflict,
			wantBody:   *serviceErr,
			wantInput:  domain.RegisterInput{Email: "user@example.com", Password: "password123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotInput domain.RegisterInput
			registerCalls := 0
			service := &MockAuthService{
				RegisterFunc: func(_ context.Context, data domain.RegisterInput) (uuid.UUID, error) {
					registerCalls++
					gotInput = data
					return tt.registerID, tt.wantErr
				},
			}
			transport := httpTransport.NewTransportHTTP(
				service,
				validator.New(),
				zap.NewNop(),
			)

			request := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBufferString(tt.body))
			response := httptest.NewRecorder()

			transport.RegisterUser(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}

			var gotBody map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &gotBody); err != nil {
				t.Fatalf("decode response body: %v", err)
			}

			wantBodyBytes, err := json.Marshal(tt.wantBody)
			if err != nil {
				t.Fatalf("encode expected body: %v", err)
			}
			var wantBody map[string]any
			if err := json.Unmarshal(wantBodyBytes, &wantBody); err != nil {
				t.Fatalf("decode expected body: %v", err)
			}

			if !reflect.DeepEqual(gotBody, wantBody) {
				t.Errorf("body = %v, want %v", gotBody, wantBody)
			}

			if tt.wantInput != (domain.RegisterInput{}) {
				if gotInput != tt.wantInput {
					t.Errorf("register input = %+v, want %+v", gotInput, tt.wantInput)
				}
				if registerCalls != 1 {
					t.Errorf("register calls = %d, want 1", registerCalls)
				}
			} else if registerCalls != 0 {
				t.Errorf("register calls = %d, want 0", registerCalls)
			}
		})
	}
}

func TestTransportHTTP_LoginUser(t *testing.T) {
	type testCase struct {
		name       string
		body       string
		tokenPair  domain.TokenPair
		wantErr    error
		wantStatus int
		wantBody   any
		wantInput  domain.LoginInput
	}

	tokenPair := domain.TokenPair{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	serviceErr := &domain.AppError{
		Code:    "ErrUnauthorized",
		Message: "wrong email or password",
		Status:  http.StatusUnauthorized,
	}

	tests := []testCase{
		{
			name:       "Успешная авторизация",
			body:       `{"email":"user@example.com","password":"password123"}`,
			tokenPair:  tokenPair,
			wantStatus: http.StatusOK,
			wantBody:   httpTransport.TokenPairResponseDTO{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken},
			wantInput:  domain.LoginInput{Email: "user@example.com", Password: "password123", IP: "203.0.113.10"},
		},
		{
			name:       "Невалидный email",
			body:       `{"email":"user@.com", "password":"password123"}`,
			wantStatus: http.StatusBadRequest,
			wantBody: domain.AppError{
				Code:    "ErrValidationFailed",
				Message: "validation failed check input fields",
			},
		},
		{
			name:       "Невалдиный json",
			body:       `{"email":`,
			wantStatus: http.StatusBadRequest,
			wantBody: domain.AppError{
				Code:    "ErrInvalidRequest",
				Message: "invalid json body",
			},
		},
		{
			name:       "Ошибка на стороне сервиса",
			body:       `{"email":"user@example.com","password":"password123"}`,
			wantErr:    serviceErr,
			wantStatus: http.StatusUnauthorized,
			wantBody:   *serviceErr,
			wantInput:  domain.LoginInput{Email: "user@example.com", Password: "password123", IP: "203.0.113.10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotInput domain.LoginInput
			loginCalls := 0
			service := &MockAuthService{
				LoginFunc: func(_ context.Context, data domain.LoginInput) (*domain.TokenPair, error) {
					loginCalls++
					gotInput = data
					return &tt.tokenPair, tt.wantErr
				},
			}

			transport := httpTransport.NewTransportHTTP(
				service,
				validator.New(),
				zap.NewNop(),
			)

			request := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(tt.body))
			request.RemoteAddr = "203.0.113.10:54321"
			response := httptest.NewRecorder()

			transport.LoginUser(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}

			var gotBody map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &gotBody); err != nil {
				t.Fatalf("decode response body: %v", err)
			}

			wantBodyBytes, err := json.Marshal(tt.wantBody)
			if err != nil {
				t.Fatalf("encode expected body: %v", err)
			}
			var wantBody map[string]any
			if err := json.Unmarshal(wantBodyBytes, &wantBody); err != nil {
				t.Fatalf("decode expected body: %v", err)
			}

			if !reflect.DeepEqual(gotBody, wantBody) {
				t.Errorf("body = %v, want = %v", gotBody, wantBody)
			}

			if tt.wantInput != (domain.LoginInput{}) {
				if gotInput != tt.wantInput {
					t.Errorf("register input = %+v, want %+v", gotInput, tt.wantInput)
				}
				if loginCalls != 1 {
					t.Errorf("login calls = %d, want 1 ", loginCalls)
				}
			} else if loginCalls != 0 {
				t.Errorf("login calls = %d, want 0", loginCalls)
			}
		})
	}
}

func TestTransportHTTP_Refresh(t *testing.T) {
	type testCase struct {
		name             string
		body             string
		tokenPair        domain.TokenPair
		wantErr          error
		wantStatus       int
		wantBody         any
		wantRefreshToken string
		wantUserAgent    string
		wantIP           string
	}

	tokenPair := domain.TokenPair{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	serviceErr := &domain.AppError{
		Code:    "ErrInternalServer",
		Message: "internal server error",
		Status:  http.StatusInternalServerError,
	}

	tests := []testCase{
		{
			name:             "Успешная замена токенов",
			body:             `{"refresh_token":"old-token"}`,
			tokenPair:        tokenPair,
			wantStatus:       http.StatusOK,
			wantBody:         httpTransport.TokenPairResponseDTO{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken},
			wantRefreshToken: "old-token",
			wantUserAgent:    "test-agent",
			wantIP:           "203.0.113.10",
		},
		{
			name:       "Невалидный json",
			body:       `{"refresh_token":`,
			wantStatus: http.StatusBadRequest,
			wantBody: domain.AppError{
				Code:    "ErrInvalidRequest",
				Message: "invalid json body",
			},
		},
		{
			name:       "Пустой refresh token",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantBody: domain.AppError{
				Code:    "ErrValidationFailed",
				Message: "validation failed check input fields",
			},
		},
		{
			name:             "Ошибка на стороне сервиса",
			body:             `{"refresh_token":"old-token"}`,
			wantErr:          serviceErr,
			wantStatus:       http.StatusInternalServerError,
			wantBody:         *serviceErr,
			wantRefreshToken: "old-token",
			wantUserAgent:    "test-agent",
			wantIP:           "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotRefreshToken, gotUserAgent, gotIP string
			refreshCalls := 0
			service := &MockAuthService{
				RefreshFunc: func(_ context.Context, refreshToken, userAgent, rawID string) (*domain.TokenPair, error) {
					refreshCalls++
					gotRefreshToken = refreshToken
					gotUserAgent = userAgent
					gotIP = rawID
					return &tt.tokenPair, tt.wantErr
				},
			}
			transport := httpTransport.NewTransportHTTP(
				service,
				validator.New(),
				zap.NewNop(),
			)

			request := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewBufferString(tt.body))
			request.RemoteAddr = "203.0.113.10:54321"
			request.Header.Set("User-Agent", "test-agent")
			response := httptest.NewRecorder()

			transport.RefreshTokens(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}

			var gotBody map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &gotBody); err != nil {
				t.Fatalf("decode response body: %v", err)
			}

			wantBodyBytes, err := json.Marshal(tt.wantBody)
			if err != nil {
				t.Fatalf("encode expected body: %v", err)
			}
			var wantBody map[string]any
			if err := json.Unmarshal(wantBodyBytes, &wantBody); err != nil {
				t.Fatalf("decode expected body: %v", err)
			}

			if !reflect.DeepEqual(gotBody, wantBody) {
				t.Errorf("body = %v, want = %v", gotBody, wantBody)
			}

			if tt.wantRefreshToken != "" {
				if gotRefreshToken != tt.wantRefreshToken {
					t.Errorf("refresh token = %q, want %q", gotRefreshToken, tt.wantRefreshToken)
				}
				if gotUserAgent != tt.wantUserAgent {
					t.Errorf("user agent = %q, want %q", gotUserAgent, tt.wantUserAgent)
				}
				if gotIP != tt.wantIP {
					t.Errorf("IP = %q, want %q", gotIP, tt.wantIP)
				}
				if refreshCalls != 1 {
					t.Errorf("refresh calls = %d, want 1", refreshCalls)
				}
			} else if refreshCalls != 0 {
				t.Errorf("refresh calls = %d, want 0", refreshCalls)
			}

		})
	}
}

func TestTransportHTTP_LogoutUser(t *testing.T) {
	type testCase struct {
		name             string
		body             string
		wantErr          error
		wantStatus       int
		wantRefreshToken string
	}

	serviceErr := &domain.AppError{
		Code:    "ErrUnauthorized",
		Message: "invalid refresh token",
		Status:  http.StatusUnauthorized,
	}

	tests := []testCase{
		{
			name:             "Успешное удаление сессии",
			body:             `{"refresh_token":"refresh-token"}`,
			wantStatus:       http.StatusNoContent,
			wantRefreshToken: "refresh-token",
		},
		{
			name:       "Невалидный json",
			body:       `{"refresh_token`,
			wantStatus: http.StatusBadRequest,
			wantErr:    nil,
		},
		{
			name:       "Пустой refresh token",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:             "Ошибка на стороне сервиса",
			body:             `{"refresh_token":"refresh-token"}`,
			wantErr:          serviceErr,
			wantStatus:       http.StatusUnauthorized,
			wantRefreshToken: "refresh-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotRefreshToken string
			logoutCalls := 0
			service := &MockAuthService{
				LogoutFunc: func(_ context.Context, refreshToken string) error {
					logoutCalls++
					gotRefreshToken = refreshToken
					return tt.wantErr
				},
			}
			transport := httpTransport.NewTransportHTTP(
				service,
				validator.New(),
				zap.NewNop(),
			)

			request := httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewBufferString(tt.body))
			response := httptest.NewRecorder()

			transport.LogoutUser(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusNoContent {
				if response.Body.Len() != 0 {
					t.Errorf("body = %q, want empty body", response.Body.String())
				}
			} else if logoutCalls == 0 && response.Body.Len() == 0 {
				t.Fatal("expected error response body")
			}

			if tt.wantRefreshToken != "" {
				if gotRefreshToken != tt.wantRefreshToken {
					t.Errorf("refresh token = %q, want %q", gotRefreshToken, tt.wantRefreshToken)
				}
				if logoutCalls != 1 {
					t.Errorf("logout calls = %d, want 1", logoutCalls)
				}
			} else if logoutCalls != 0 {
				t.Errorf("logout calls = %d, want 0", logoutCalls)
			}
		})
	}
}

func TestTransportHTTP_GetMe(t *testing.T) {
	userID := uuid.New()
	createdAt := time.Date(2026, time.October, 29, 12, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)
	user := &domain.User{
		ID:         userID,
		Email:      "user@example.com",
		Role:       domain.RoleUser,
		IsVerified: true,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
	}
	serviceErr := &domain.AppError{
		Code:    "ErrInternalServer",
		Message: "internal server error",
		Status:  http.StatusInternalServerError,
	}

	tests := []struct {
		name       string
		claims     *jwt.CustomClaims
		parseErr   error
		corruptCtx bool
		getMeUser  *domain.User
		getMeErr   error
		wantStatus int
		wantBody   any
		wantUserID uuid.UUID
		getMeCalls int
	}{
		{
			name:       "Успешное получение пользователя",
			claims:     &jwt.CustomClaims{UserID: userID.String(), Role: string(domain.RoleUser)},
			getMeUser:  user,
			wantStatus: http.StatusOK,
			wantBody: httpTransport.UserResponseDTO{
				ID: user.ID, Email: user.Email, Role: user.Role, IsVerified: user.IsVerified,
				CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
			},
			wantUserID: userID,
			getMeCalls: 1,
		},
		{
			name:       "Нет авторизации",
			wantStatus: http.StatusUnauthorized,
			wantBody: domain.AppError{
				Code: "ErrUnauthorized", Message: "missing authorization header",
			},
		},
		{
			name:       "Ошибка получения пользователя",
			claims:     &jwt.CustomClaims{UserID: userID.String()},
			getMeErr:   serviceErr,
			wantStatus: http.StatusInternalServerError,
			wantBody:   *serviceErr,
			wantUserID: userID,
			getMeCalls: 1,
		},
		{
			name:       "Ошибка извлечения uuid из контекста (Ветка if !ok)",
			claims:     &jwt.CustomClaims{UserID: userID.String()},
			corruptCtx: true,
			wantStatus: http.StatusUnauthorized,
			wantBody: domain.AppError{
				Code: "ErrUnauthorized", Message: "unauthorized",
			},
			getMeCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotUserID uuid.UUID
			getMeCalls := 0
			service := &MockAuthService{
				GetMeFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
					getMeCalls++
					gotUserID = id
					return tt.getMeUser, tt.getMeErr
				},
				ParseTokenFunc: func(string) (*jwt.CustomClaims, error) {
					return tt.claims, tt.parseErr
				},
			}
			transport := httpTransport.NewTransportHTTP(service, validator.New(), zap.NewNop())
			request := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
			if tt.claims != nil {
				request.Header.Set("Authorization", "Bearer access-token")
			}
			response := httptest.NewRecorder()

			if tt.corruptCtx {
				transport.GetMe(response, request)
			} else {
				transport.AuthMiddleware(http.HandlerFunc(transport.GetMe)).ServeHTTP(response, request)
			}

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}

			var gotBody map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &gotBody); err != nil {
				t.Fatalf("decode response body: %v", err)
			}
			wantBodyBytes, err := json.Marshal(tt.wantBody)
			if err != nil {
				t.Fatalf("encode expected body: %v", err)
			}
			var wantBody map[string]any
			if err := json.Unmarshal(wantBodyBytes, &wantBody); err != nil {
				t.Fatalf("decode expected body: %v", err)
			}
			if !reflect.DeepEqual(gotBody, wantBody) {
				t.Errorf("body = %v, want %v", gotBody, wantBody)
			}
			if getMeCalls != tt.getMeCalls {
				t.Errorf("GetMe calls = %d, want %d", getMeCalls, tt.getMeCalls)
			}
			if tt.wantUserID != uuid.Nil && gotUserID != tt.wantUserID {
				t.Errorf("user ID = %s, want %s", gotUserID, tt.wantUserID)
			}
		})
	}
}
