package auth

import (
	"github.com/LionJr/auth/internal/config"
	"github.com/LionJr/auth/internal/smtp"
	"github.com/LionJr/auth/pkg/token_manager"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Service struct {
	config *config.AppConfig
	Logger *zap.Logger

	PgRepo      PgRepo
	RedisClient *redis.Client

	tokenManager *token_manager.TokenManager

	smtp *smtp.Smtp
}

func NewService(cfg *config.AppConfig, logger *zap.Logger, repo PgRepo, redisClient *redis.Client, tokenManager *token_manager.TokenManager, smtp *smtp.Smtp) *Service {
	return &Service{
		config: cfg,
		Logger: logger,

		PgRepo:      repo,
		RedisClient: redisClient,

		tokenManager: tokenManager,

		smtp: smtp,
	}
}
