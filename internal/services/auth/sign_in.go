package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/LionJr/auth/internal/models"
)

// SignInHandler           godoc
// @Summary                Sign in
// @Description            Sign in by email address
// @Tags                   Auth
// @Accept                 json
// @Produce                json
// @Param                  req              body      models.SignInRequest true  "email address"
// @Success      		   200              {object}  models.SignInResponse
// @Failure      		   400              {object}  models.ErrorResponse
// @Failure      		   500              {object}  models.ErrorResponse
// @Router       		   /auth/sign-in [post]
func (s *Service) SignInHandler(ctx *gin.Context) {
	var req models.SignInRequest
	if err := ctx.BindJSON(&req); err != nil {
		s.Logger.Info("auth.SignInHandler: unmarshal request body", zap.Error(err))
		sendErrorResponse(ctx, "Invalid request body", http.StatusBadRequest)
		return
	}

	userId, err := s.PgRepo.GetUserIdByEmail(ctx, req.Email)
	if err != nil {
		s.Logger.Info("auth.SignInHandler: get user id from db", zap.Error(err))
		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = s.smtp.SendCode(ctx, req.Email, userId)
	if err != nil {
		s.Logger.Info("auth.SignInHandler: send OTP to user", zap.Error(err))
		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := models.SignInResponse{
		Message: "Код успешно отправлен",
		UserId:  userId,
	}
	sendSuccessResponse(ctx, resp, http.StatusOK)
}
