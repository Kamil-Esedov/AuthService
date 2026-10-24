package service

import (
	"auth-service/internal/domain"
	"auth-service/pkg/jwt"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Postgres interface {
	Register(ctx context.Context, user *domain.User) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, userID uuid.UUID) (*domain.User, error)

	CreateSession(ctx context.Context, session *domain.Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	RotateSession(ctx context.Context, oldSession uuid.UUID, newSession *domain.Session) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}

type TokenManager interface {
	NewAccessToken(userID, role string, ttl time.Duration) (string, error)
	Parse(accessToken string) (*jwt.CustomClaims, error)
	NewRefreshToken() (string, error)
}

type AuthService struct {
	tokenManager TokenManager
	accessTTL    time.Duration
	refreshTTL   time.Duration

	postgres       Postgres
	passwordHasher PasswordHasher
	logger         *zap.Logger
}

func NewAuthService(
	tokenManager TokenManager,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	postgres Postgres,
	passwordHasher PasswordHasher,
	logger *zap.Logger,
) *AuthService {
	return &AuthService{
		tokenManager:   tokenManager,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
		postgres:       postgres,
		passwordHasher: passwordHasher,
		logger:         logger,
	}
}

func (s *AuthService) Register(ctx context.Context, data domain.RegisterInput) (uuid.UUID, error) {
	passwordHash, err := s.passwordHasher.Hash(data.Password)
	if err != nil {
		s.logger.Error("failed to hash password", zap.Error(err))

		return uuid.Nil, domain.NewErrInternal(err)
	}

	user := domain.User{
		Email:        data.Email,
		PasswordHash: passwordHash,
		Role:         domain.RoleUser,
	}

	return s.postgres.Register(ctx, &user)
}

func (s *AuthService) Login(ctx context.Context, data domain.LoginInput) (*domain.TokenPair, error) {
	user, err := s.postgres.GetByEmail(ctx, data.Email)
	if err != nil {
		var appErr *domain.AppError
		if errors.As(err, &appErr) && appErr.Code == "ErrUserNotFound" {
			s.logger.Info("login failed: user not found", zap.String("email", data.Email))
			return nil, &domain.AppError{
				Code:    "ErrUnauthorized",
				Message: "incorrect email or password",
				Status:  http.StatusUnauthorized,
				Cause:   err,
			}
		}
		return nil, err
	}

	if !s.passwordHasher.Compare(data.Password, user.PasswordHash) {
		s.logger.Info("login failed: invalid credentials")

		return nil, &domain.AppError{
			Code:    "ErrUnauthorized",
			Message: "incorrect email or password",
			Status:  http.StatusUnauthorized,
		}
	}

	if user.IsBlocked {
		s.logger.Warn("login attempt by blocked user", zap.String("user_id", user.ID.String()))

		return nil, &domain.AppError{
			Code:    "ErrForbidden",
			Message: "user account is blocked",
			Status:  http.StatusForbidden,
		}
	}

	ip, err := netip.ParseAddr(data.IP)
	if err != nil {
		s.logger.Warn("failed to parse client IP", zap.String("ip", data.IP))
		ip = netip.IPv4Unspecified()
	}

	tokens, session, err := s.issueTokens(user, data.UserAgent, ip)
	if err != nil {
		return nil, err
	}

	if err := s.postgres.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	return tokens, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken, userAgent, rawID string) (*domain.TokenPair, error) {
	tokenHash := hashToken(refreshToken)

	oldSession, err := s.postgres.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if time.Now().After(oldSession.ExpiresAt) {
		return nil, &domain.AppError{
			Code:    "ErrUnauthorized",
			Message: "refresh token expired",
			Status:  http.StatusUnauthorized,
		}
	}

	user, err := s.postgres.GetByID(ctx, oldSession.UserID)
	if err != nil {
		return nil, err
	}

	if user.IsBlocked {
		return nil, &domain.AppError{
			Code:    "ErrForbidden",
			Message: "user account is blocked",
			Status:  http.StatusForbidden,
		}
	}

	ip, err := netip.ParseAddr(rawID)
	if err != nil {
		ip = oldSession.IP
	}

	tokens, newSession, err := s.issueTokens(user, userAgent, ip)
	if err != nil {
		return nil, err
	}

	if err := s.postgres.RotateSession(ctx, oldSession.ID, newSession); err != nil {
		return nil, err
	}

	return tokens, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := hashToken(refreshToken)
	session, err := s.postgres.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return err
	}

	return s.postgres.DeleteSession(ctx, session.ID)
}

func (s *AuthService) GetMe(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.postgres.GetByID(ctx, userID)
}

func (s *AuthService) ParseToken(accessToken string) (*jwt.CustomClaims, error) {
	claims, err := s.tokenManager.Parse(accessToken)
	if err != nil {
		if errors.Is(err, jwt.ErrExpiredToken) {
			return nil, &domain.AppError{
				Code:    "ErrTokenExpired",
				Message: "access token has expired",
				Status:  http.StatusUnauthorized,
				Cause:   err,
			}
		}

		return nil, &domain.AppError{
			Code:    "ErrUnauthorized",
			Message: "invalid access token",
			Status:  http.StatusUnauthorized,
			Cause:   err,
		}
	}

	return claims, nil
}

func (s *AuthService) issueTokens(user *domain.User, userAgent string, ip netip.Addr) (*domain.TokenPair, *domain.Session, error) {
	accessToken, err := s.tokenManager.NewAccessToken(user.ID.String(), string(user.Role), s.accessTTL)
	if err != nil {
		s.logger.Error("failed to generate access token", zap.Error(err))
		return nil, nil, domain.NewErrInternal(err)
	}

	refreshToken, err := s.tokenManager.NewRefreshToken()
	if err != nil {
		s.logger.Error("failed to generate refresh token", zap.Error(err))
		return nil, nil, domain.NewErrInternal(err)
	}

	now := time.Now()
	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: hashToken(refreshToken),
		UserAgent: userAgent,
		IP:        ip,
		ExpiresAt: now.Add(s.refreshTTL),
		CreatedAt: now,
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, session, nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
