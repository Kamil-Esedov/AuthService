package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	gRPCserverPort int
	DatabaseURL    string
	HashCost       int
	AppPort        int
}

func MustLoad() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		gRPCserverPort: getEnvAsInt("GRPC_PORT", 50051),
		DatabaseURL:    getEnvRequired("DB_URL"),
		HashCost:       getEnvAsInt("HASH_COST", 10),
		AppPort:        getEnvAsInt("APP_PORT", 8080),
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
