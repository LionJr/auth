package app

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/LionJr/auth/internal/app/http/server"
	"github.com/LionJr/auth/internal/config"
	"github.com/LionJr/auth/internal/repositories/postgres"
	redisrepo "github.com/LionJr/auth/internal/repositories/redis"
	"github.com/LionJr/auth/internal/services/auth"
	"github.com/LionJr/auth/internal/smtp"
	"github.com/LionJr/auth/pkg/token_manager"
)

const (
	name            = "auth"
	configsPath     = "configs"
	shutdownTimeout = 15 * time.Second
)

type Application struct {
	cfg            *config.AppConfig
	logger         *zap.Logger
	postgresClient *sqlx.DB
	redisClient    *goredis.Client
	authService    *auth.Service
	tokenManager   *token_manager.TokenManager
	http           *server.Server
}

func New(ctx context.Context) (*Application, error) {
	var version, environment, logLevel string
	flag.StringVar(&version, "v", "", "version")
	flag.StringVar(&environment, "e", "local", "environment")
	flag.StringVar(&logLevel, "ll", "info", "logging level")
	flag.Parse()

	cfg, err := config.NewAppConfig(fmt.Sprintf("%s/%s.yml", configsPath, environment))
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}

	logger.Info(
		"flags",
		zap.String("name", name),
		zap.String("version", version),
		zap.String("environment", environment),
		zap.String("log_level", logLevel),
	)

	pgClient, err := postgres.NewPostgresDB(cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	redisClient, err := redisrepo.NewRedisClient(ctx, cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("connect redis: %w", err)
	}

	tokenManager, err := token_manager.NewManager(cfg.Token.AccessSecretKey, cfg.Token.RefreshSecretKey)
	if err != nil {
		return nil, fmt.Errorf("init token manager: %w", err)
	}

	smtpClient := smtp.NewSmtp(cfg.SMTP, redisClient, tokenManager)
	authService := auth.NewService(
		cfg,
		logger,
		postgres.NewAuthRepository(pgClient),
		redisClient,
		tokenManager,
		smtpClient,
	)

	return &Application{
		cfg:            cfg,
		logger:         logger,
		postgresClient: pgClient,
		redisClient:    redisClient,
		authService:    authService,
		tokenManager:   tokenManager,
		http:           server.New(cfg, logger, authService, tokenManager),
	}, nil
}

func (a *Application) Run(ctx context.Context) error {
	a.logger.Info("application started")
	return a.http.Run(ctx)
}

func (a *Application) Shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if a.http != nil {
		if err := a.http.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("http shutdown failed", zap.Error(err))
		}
	}

	if a.postgresClient != nil {
		a.logger.Info("closing postgres connection")
		if err := a.postgresClient.Close(); err != nil {
			a.logger.Error("postgres close failed", zap.Error(err))
		}
	}

	if a.redisClient != nil {
		a.logger.Info("closing redis connection")
		if err := a.redisClient.Close(); err != nil {
			a.logger.Error("redis close failed", zap.Error(err))
		}
	}

	if a.logger != nil {
		a.logger.Info("application stopped")
		if err := a.logger.Sync(); err != nil {
			a.logger.Error("logger sync failed", zap.Error(err))
		}
	}
}
