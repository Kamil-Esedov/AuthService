package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	GRPCPort         int
	HashCost         int
	AppPort          int
	JWTSecret        string
	AccessTokenTTL   int
	RefreshTokenTTL  int
	PostgresDB       string
	PostgresPort     int
	PostgresPassword string
	PostgresUser     string
	PostgresHost     string
}

func MustLoad() *Config {
	if err := godotenv.Load(".env.local"); err == nil {
		log.Println("Loaded local config: .env.local")
	}

	if err := godotenv.Load(".env"); err == nil {
		log.Println("Loaded base config: .env")
	}

	cfg := &Config{
		GRPCPort:         getEnvAsInt("GRPC_PORT", 50051),
		HashCost:         getEnvAsInt("HASH_COST", 10),
		AppPort:          getEnvAsInt("APP_PORT", 8080),
		JWTSecret:        getEnvRequired("JWT_SECRET"),
		AccessTokenTTL:   getEnvAsInt("ACCESS_TOKEN_TTL", 15),
		RefreshTokenTTL:  getEnvAsInt("REFRESH_TOKEN_TTL", 720),
		PostgresDB:       getEnvRequired("POSTGRES_DB"),
		PostgresPort:     getEnvAsInt("POSTGRES_PORT", 5432),
		PostgresPassword: getEnvRequired("POSTGRES_PASSWORD"),
		PostgresUser:     getEnvRequired("POSTGRES_USER"),
		PostgresHost:     getEnvRequired("POSTGRES_HOST"),
	}

	return cfg
}

func getEnvRequired(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("required env variable %s is not set", key)
	}

	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("env variable %s must be integer", key)
	}

	if intValue <= 0 {
		log.Fatalf("env variable %s must be greater than 0", key)
	}

	return intValue
}
