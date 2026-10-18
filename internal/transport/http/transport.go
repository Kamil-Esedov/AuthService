package httpTransport

import (
	"auth-service/internal/domain"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/go-playground/validator"
	"github.com/google/uuid"

	"go.uber.org/zap"
)

/*
	POST /api/v1/auth/register	регистрация
	POST /api/v1/auth/login		вход
	POST /api/v1/auth/refresh	обновление токенов
	POST /api/v1/auth/logout	завершение сессии
	GET /api/v1/users/me		данные текущего пользователя
*/

type AuthService interface {
	Register(ctx context.Context, data domain.RegisterInput) (uuid.UUID, error)
	Login(ctx context.Context, data domain.LoginInput) (*domain.User, error)
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

func (t *Transport) RegisterUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var data RegisterRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		t.writeError(w, &domain.AppError{
			Code:    "ErrInvalidRequest",
			Message: "invalid data input",
			Status:  http.StatusBadRequest,
			Cause:   err,
		})

		return
	}

	if err := t.validator.Struct(data); err != nil {
		t.writeError(w, &domain.AppError{
			Code:    "ErrInvalidRequest",
			Message: "invalid data input",
			Status:  http.StatusBadRequest,
			Cause:   err,
		})

		return
	}

	registerData := domain.RegisterInput{
		Email:    data.Email,
		Password: data.Password,
	}

	id, err := t.authService.Register(ctx, registerData)
	if err != nil {
		t.writeError(w, err)
		return
	}

	response := RegisterResponseDTO{
		ID: id,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.logger.Error("failed to encode response", zap.Error(err))
	}
}

func (t *Transport) LoginUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var data LoginRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		t.writeError(w, &domain.AppError{
			Code:    "ErrInvalidRequest",
			Message: "invalid data input",
			Status:  http.StatusBadRequest,
			Cause:   err,
		})

		return
	}

	if err := t.validator.Struct(data); err != nil {
		t.writeError(w, &domain.AppError{
			Code:    "ErrInvalidRequest",
			Message: "invalid data input",
			Status:  http.StatusBadRequest,
			Cause:   err,
		})

		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	loginData := domain.LoginInput{
		Email:     data.Email,
		Password:  data.Password,
		UserAgent: r.UserAgent(),
		IP:        ip,
	}

	user, err := t.authService.Login(ctx, loginData)
	if err != nil {
		t.writeError(w, err)
		return
	}

	response := LoginResponseDTO{
		User: UserResponseDTO{
			ID:         user.ID,
			Email:      user.Email,
			Role:       user.Role,
			IsVerified: user.IsVerified,
			CreatedAt:  user.CreatedAt,
			UpdatedAt:  user.UpdatedAt,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.logger.Error("failed to encode response", zap.Error(err))
	}
}

func (t *Transport) writeError(w http.ResponseWriter, err error) {
	var appErr *domain.AppError

	if !errors.As(err, &appErr) {
		t.logger.Error("unhandled request error", zap.Error(err))
		appErr = domain.NewErrInternal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.Status)

	if encodeErr := json.NewEncoder(w).Encode(appErr); encodeErr != nil {
		t.logger.Error("failed to encode error response", zap.Error(encodeErr))
	}
}
