package main

import (
	"auth-service/internal/config"
	"auth-service/internal/service"
	"auth-service/internal/storage/postgres"
	httpTransport "auth-service/internal/transport/http"
	"auth-service/pkg/hash"
	"auth-service/pkg/logger"
	"context"
	"log"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func main() {
	cfg := config.MustLoad()

	logger, err := logger.NewLogger()
	if err != nil {
		log.Fatal("failed to init logger. Error: ", err)
	}

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("failed to open pool", zap.Error(err))
	}
	defer dbpool.Close()

	if err := dbpool.Ping(ctx); err != nil {
		logger.Fatal("failed to connect to the database", zap.Error(err))
	}

	hasher := hash.NewBcryptHasher(cfg.HashCost)
	validator := validator.New()

	postgres := postgres.NewPostgres(dbpool, logger)
	authService := service.NewAuthService(postgres, hasher, logger)
	httpTransport := httpTransport.NewTransportHTTP(authService, validator, logger)

	router := chi.NewRouter()

	router.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", httpTransport.RegisterUser)
		r.Post("/login", httpTransport.LoginUser)
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

	logger.Info("http server started on :8080")

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
