package main

import (
	"auth-service/internal/config"
	"auth-service/internal/service"
	"auth-service/internal/storage/postgres"
	httpTransport "auth-service/internal/transport/http"
	"auth-service/pkg/hash"
	"auth-service/pkg/jwt"
	"auth-service/pkg/logger"
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func main() {
	cfg := config.MustLoad()

	logger, err := logger.NewLogger()
	if err != nil {
		log.Fatal("failed to init logger. Error: ", err)
	}

	dbURL := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.PostgresUser,
		cfg.PostgresPassword,
		cfg.PostgresHost,
		cfg.PostgresPort,
		cfg.PostgresDB,
	)

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		logger.Fatal("failed to open pool", zap.Error(err))
	}
	defer dbpool.Close()

	if err := dbpool.Ping(ctx); err != nil {
		logger.Fatal("failed to connect to the database", zap.Error(err))
	}

	hasher := hash.NewBcryptHasher(cfg.HashCost)
	validator := validator.New()

	tokenManager, err := jwt.NewManager(cfg.JWTSecret)
	if err != nil {
		logger.Fatal("secret key is not set")
	}

	postgres := postgres.NewPostgres(dbpool, logger)
	authService := service.NewAuthService(tokenManager, time.Minute*time.Duration(cfg.AccessTokenTTL), time.Hour*time.Duration(cfg.RefreshTokenTTL), postgres, hasher, logger)
	httpTransport := httpTransport.NewTransportHTTP(authService, validator, logger)

	router := chi.NewRouter()

	router.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", httpTransport.RegisterUser)
		r.Post("/login", httpTransport.LoginUser)
		r.Post("/refresh", httpTransport.RefreshTokens)
		r.Post("/logout", httpTransport.LogoutUser)
	})

	router.Group(func(r chi.Router) {
		r.Use(httpTransport.AuthMiddleware)

		r.Get("/api/users/me", httpTransport.GetMe)
	})

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.AppPort),
		Handler:           router,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("failed to start http server", zap.Error(err))
			panic(err)
		}
	}()

	logger.Info("http server started on", zap.Int("port", cfg.AppPort))

	ctxApp, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctxApp.Done()

	logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server was forced to shutdown", zap.Error(err))
	}

	logger.Info("application shutdown complited")
}
