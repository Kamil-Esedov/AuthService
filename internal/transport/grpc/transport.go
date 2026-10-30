package grpc

import (
	authv1 "auth-service/gen/auth/v1"
	"auth-service/internal/domain"
	"auth-service/pkg/jwt"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	authv1.UnimplementedAuthServiceServer
	authService AuthService
	validator   *validator.Validate
	logger      *zap.Logger
}

func NewTransportGRPC(authService AuthService, validator *validator.Validate, logger *zap.Logger) *Transport {
	return &Transport{
		authService: authService,
		validator:   validator,
		logger:      logger,
	}
}

func (t *Transport) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := t.validator.Struct(struct {
		Email    string `validate:"required,email"`
		Password string `validate:"required,min=8,max=72"`
	}{Email: req.GetEmail(), Password: req.GetPassword()}); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed: email or password is invalid")
	}

	id, err := t.authService.Register(ctx, domain.RegisterInput{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, t.mapError(err)
	}

	return &authv1.RegisterResponse{UserId: id.String()}, nil
}

func (t *Transport) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.TokenPair, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := t.validator.Struct(struct {
		Email    string `validate:"required,email"`
		Password string `validate:"required"`
	}{Email: req.GetEmail(), Password: req.GetPassword()}); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed: email or password invalid")
	}

	tokens, err := t.authService.Login(ctx, domain.LoginInput{
		Email:     req.GetEmail(),
		Password:  req.GetPassword(),
		UserAgent: incomingUserAgent(ctx),
		IP:        incomingClientIP(ctx),
	})
	if err != nil {
		return nil, t.mapError(err)
	}

	return tokenPairToProto(tokens), nil
}

func (t *Transport) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.TokenPair, error) {
	if req == nil || strings.TrimSpace(req.GetRefreshToken()) == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is requred")
	}

	tokens, err := t.authService.Refresh(ctx, req.GetRefreshToken(), incomingUserAgent(ctx), incomingClientIP(ctx))
	if err != nil {
		return nil, t.mapError(err)
	}

	return tokenPairToProto(tokens), nil
}

func (t *Transport) Logout(ctx context.Context, req *authv1.LogoutRequest) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	if err := t.authService.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, t.mapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (t *Transport) GetMe(ctx context.Context, _ *authv1.GetMeRequest) (*authv1.User, error) {
	accessToken, err := bearerToken(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := t.authService.ParseToken(accessToken)
	if err != nil {
		return nil, t.mapError(err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid user id in access token")
	}

	user, err := t.authService.GetMe(ctx, userID)
	if err != nil {
		return nil, t.mapError(err)
	}

	return userToProto(user), nil
}

func userToProto(user *domain.User) *authv1.User {
	role := authv1.Role_ROLE_UNSPECIFIED
	switch user.Role {
	case domain.RoleUser:
		role = authv1.Role_ROLE_USER
	case domain.RoleAdmin:
		role = authv1.Role_ROLE_ADMIN
	}

	return &authv1.User{
		Id: user.ID.String(), Email: user.Email, Role: role, IsVerified: user.IsVerified,
		CreatedAt: timestamppb.New(user.CreatedAt), UpdatedAt: timestamppb.New(user.UpdatedAt),
	}
}

func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing authorization metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization metadata")
	}

	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", status.Error(codes.Unauthenticated, "authorization metadata must user Bearer token")
	}

	return parts[1], nil
}

func tokenPairToProto(tokens *domain.TokenPair) *authv1.TokenPair {
	return &authv1.TokenPair{AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken}
}

func incomingClientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err != nil {
		return host
	}

	return p.Addr.String()
}

func incomingUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("user-agent")
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func (t *Transport) mapError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "request canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request deadline exeeded")
	}

	var appErr *domain.AppError
	if !errors.As(err, &appErr) {
		t.logger.Error("unhandled gRPC request error", zap.Error(err))
		return status.Error(codes.Internal, "internal server error")
	}

	code := codes.Internal
	switch appErr.Status {
	case http.StatusBadRequest:
		code = codes.InvalidArgument
	case http.StatusUnauthorized:
		code = codes.Unauthenticated
	case http.StatusForbidden:
		code = codes.PermissionDenied
	case http.StatusNotFound:
		code = codes.NotFound
	case http.StatusConflict:
		code = codes.AlreadyExists
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		code = codes.DeadlineExceeded
	case http.StatusTooManyRequests:
		code = codes.ResourceExhausted
	case http.StatusServiceUnavailable:
		code = codes.Unavailable
	case 499:
		code = codes.Canceled
	}
	if code == codes.Internal {
		t.logger.Error("internal application error during gRPC request", zap.String("code", appErr.Code), zap.Error(err))
		return status.Error(code, "interval server error")
	}

	return status.Error(code, appErr.Message)
}
