package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"

	"github.com/LionJr/auth/internal/config"
	"github.com/LionJr/auth/internal/services/auth"
	"github.com/LionJr/auth/pkg/token_manager"

	_ "github.com/LionJr/auth/docs"
)

type Server struct {
	cfg          *config.AppConfig
	logger       *zap.Logger
	authService  *auth.Service
	tokenManager *token_manager.TokenManager
	srv          *http.Server
}

func New(
	cfg *config.AppConfig,
	logger *zap.Logger,
	authService *auth.Service,
	tokenManager *token_manager.TokenManager,
) *Server {
	return &Server{
		cfg:          cfg,
		logger:       logger,
		authService:  authService,
		tokenManager: tokenManager,
		srv: &http.Server{
			Handler:      initHandlers(authService),
			Addr:         ":" + strconv.Itoa(cfg.HTTP.Port),
			ReadTimeout:  cfg.HTTP.ReadTimeout,
			WriteTimeout: cfg.HTTP.WriteTimeout,
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		s.logger.Info(
			"http server listening",
			zap.String("domain", s.cfg.HTTP.Domain),
			zap.Int("port", s.cfg.HTTP.Port),
		)

		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutdown signal received")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	s.logger.Info("http server stopped")
	return nil
}

func initHandlers(authService *auth.Service) *gin.Engine {
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowMethods:     []string{"GET, POST, OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "User-Agent", "Referrer", "Host", "X-Forwarded-For"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOrigins:     []string{"http://localhost:8080"},
		MaxAge:           86400,
	}))

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	api := router.Group("/api")
	authRouter := api.Group("/auth")
	authRouter.POST("/sign-in", authService.SignInHandler)
	authRouter.POST("/check-code", authService.CheckCodeHandler)
	authRouter.POST("/refresh", authService.RefreshHandler)

	return router
}
