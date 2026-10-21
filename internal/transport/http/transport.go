package httpTransport

import (
	"auth-service/internal/domain"
	"auth-service/pkg/jwt"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"go.uber.org/zap"
)

/*
	POST /api/auth/register	регистрация
	POST /api/auth/login		вход
	POST /api/auth/refresh	обновление токенов
	POST /api/auth/logout	завершение сессии
	GET /api/users/me		данные текущего пользователя
*/

type ctxKey string

const (
	ctxKeyUserID ctxKey = "user_id"
	ctxKeyRole   ctxKey = "role"
)

type AuthService interface {
	Register(ctx context.Context, data domain.RegisterInput) (uuid.UUID, error)
	Login(ctx context.Context, data domain.LoginInput) (*domain.TokenPair, error)
	Refresh(ctx context.Context, refreshToken, userAgent, rawID string) (*domain.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	GetMe(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	ParseToken(accessToken string) (*jwt.CustomClaims, error)
}

type Transport struct {
	authService AuthService
	logger      *zap.Logger
	validator   *validator.Validate
}

func NewTransportHTTP(authService AuthService, validator *validator.Validate, logger *zap.Logger) *Transport {
	return &Transport{
		authService: authService,
		validator:   validator,
		logger:      logger,
	}
}

// POST /api/auth/register
func (t *Transport) RegisterUser(w http.ResponseWriter, r *http.Request) {
	var data RegisterRequestDTO
	if !t.decodeAndValidate(w, r, &data) {
		return
	}

	id, err := t.authService.Register(r.Context(), domain.RegisterInput{
		Email:    data.Email,
		Password: data.Password,
	})
	if err != nil {
		t.writeError(w, err)
		return
	}

	t.writeJSON(w, http.StatusCreated, RegisterResponseDTO{ID: id})
}

// POST api/auth/login
func (t *Transport) LoginUser(w http.ResponseWriter, r *http.Request) {
	var data LoginRequestDTO
	if !t.decodeAndValidate(w, r, &data) {
		return
	}

	tokens, err := t.authService.Login(r.Context(), domain.LoginInput{
		Email:     data.Email,
		Password:  data.Password,
		UserAgent: r.UserAgent(),
		IP:        extractIP(r),
	})
	if err != nil {
		t.writeError(w, err)
		return
	}

	t.writeJSON(w, http.StatusOK, TokenPairResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

// POST /api/auth/refresh
func (t *Transport) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var data RefreshRequestDTO
	if !t.decodeAndValidate(w, r, &data) {
		return
	}

	tokens, err := t.authService.Refresh(r.Context(), data.RefreshToken, r.UserAgent(), extractIP(r))
	if err != nil {
		t.writeError(w, err)
		return
	}

	t.writeJSON(w, http.StatusOK, TokenPairResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

// POST /api/auth/logout
func (t *Transport) LogoutUser(w http.ResponseWriter, r *http.Request) {
	var data LogoutRequestDTO
	if !t.decodeAndValidate(w, r, &data) {
		return
	}

	if err := t.authService.Logout(r.Context(), data.RefreshToken); err != nil {
		t.writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /api/users/me
func (t *Transport) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxKeyUserID).(uuid.UUID)
	if !ok {
		t.writeError(w, &domain.AppError{
			Code:    "ErrUnauthorized",
			Message: "unauthorized",
			Status:  http.StatusUnauthorized,
		})
		return
	}

	user, err := t.authService.GetMe(r.Context(), userID)
	if err != nil {
		t.writeError(w, err)
		return
	}

	t.writeJSON(w, http.StatusOK, UserResponseDTO{
		ID:         user.ID,
		Email:      user.Email,
		Role:       user.Role,
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	})
}

func (t *Transport) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			t.writeError(w, &domain.AppError{
				Code:    "ErrUnauthorized",
				Message: "missing authorization header",
				Status:  http.StatusUnauthorized,
			})
			return
		}

		parts := strings.Fields(authHeader)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			t.writeError(w, &domain.AppError{
				Code:    "ErrUnauthorized",
				Message: "invalid authorization header format",
				Status:  http.StatusUnauthorized,
			})
			return
		}

		claims, err := t.authService.ParseToken(parts[1])
		if err != nil {
			t.writeError(w, err)
			return
		}

		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			t.writeError(w, &domain.AppError{
				Code:    "ErrUnauthorized",
				Message: "invalid user id in token",
				Status:  http.StatusUnauthorized,
			})
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
		ctx = context.WithValue(ctx, ctxKeyRole, claims.Role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (t *Transport) writeError(w http.ResponseWriter, err error) {
	var appErr *domain.AppError

	if !errors.As(err, &appErr) {
		t.logger.Error("unhandled request error", zap.Error(err))
		appErr = domain.NewErrInternal(err)
	}

	if appErr.Status < 100 || appErr.Status > 599 {
		appErr.Status = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.Status)

	if encodeErr := json.NewEncoder(w).Encode(appErr); encodeErr != nil {
		t.logger.Error("failed to encode error response", zap.Error(encodeErr))
	}
}

func (t *Transport) decodeAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		t.writeError(w, &domain.AppError{
			Code:    "ErrInvalidRequest",
			Message: "invalid json body",
			Status:  http.StatusBadRequest,
			Cause:   err,
		})
		return false
	}

	if err := t.validator.Struct(dst); err != nil {
		t.writeError(w, &domain.AppError{
			Code:    "ErrValidationFailed",
			Message: "validation failed check input fields",
			Status:  http.StatusBadRequest,
			Cause:   err,
		})
		return false
	}

	return true
}

func (t *Transport) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		t.logger.Error("failed to encode response", zap.Error(err))
	}
}

func extractIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}
