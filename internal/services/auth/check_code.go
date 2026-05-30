package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"test-auth/internal/models"
)

// CheckCodeHandler       godoc
// @Summary      		  Check code
// @Description  		  Check code sent to user's email address
// @Tags         		  Auth
// @Accept       		  json
// @Produce      		  json
// @Param        		  req              body      models.CheckCodeRequest true  "check code request"
// @Param                 X-Forwarded-For  header    string                  true  "IP address"
// @Param                 user_id          query     string                  true  "User id"
// @Success        		  200              {object}  models.CheckCodeResponse
// @Failure      		  400              {object}  models.ErrorResponse
// @Failure      		  500              {object}  models.ErrorResponse
// @Router       		  /auth/check-code [post]
func (s *Service) CheckCodeHandler(ctx *gin.Context) {
	var req models.CheckCodeRequest
	if err := ctx.BindJSON(&req); err != nil {
		s.Logger.Info("auth.CheckCodeHandler: unmarshal request body", zap.Error(err))
		sendErrorResponse(ctx, "Invalid request body", http.StatusBadRequest)
		return
	}

	userId := ctx.Query("user_id")
	if userId == "" {
		s.Logger.Info("auth.CheckCodeHandler: empty user id")
		sendErrorResponse(ctx, "Invalid user id", http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("user_%s", userId)
	code := ""
	strCmd := s.RedisClient.Get(ctx, key)

	data, err := strCmd.Result()
	if err != nil {
		s.Logger.Info("auth.CheckCodeHandler: get result from redis failed", zap.Error(err))
		sendErrorResponse(ctx, "Incorrect code", http.StatusBadRequest)
		return
	}

	err = jsoniter.UnmarshalFromString(data, &code)
	if err != nil {
		s.Logger.Info("auth.CheckCodeHandler: unmarshal result from redis failed", zap.Error(err))
		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	if code != req.Code {
		s.Logger.Info("auth.CheckCodeHandler: invalid code", zap.String("code", code), zap.String("request code", req.Code))
		sendErrorResponse(ctx, "Incorrect code", http.StatusBadRequest)
		return
	}

	intCmd := s.RedisClient.Del(ctx, key)
	_, _ = intCmd.Result()

	ips := strings.Split(ctx.GetHeader("X-Forwarded-For"), ",")
	userIP := ips[0]
	if userIP == "" {
		s.Logger.Info("auth.CheckCodeHandler: empty user ip")
		sendErrorResponse(ctx, "Invalid user ip", http.StatusBadRequest)
		return
	}

	tokensId := uuid.NewString()

	accessToken, err := s.tokenManager.NewAccessToken(userId, tokensId, userIP, s.config.Token.AccessTTL)
	if err != nil {
		s.Logger.Info("auth.CheckCodeHandler: create access token failed", zap.Error(err))
		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	refreshToken, err := s.tokenManager.NewRefreshToken(tokensId, userIP, s.config.Token.RefreshTTL)
	if err != nil {
		s.Logger.Info("auth.CheckCodeHandler: create refresh token failed", zap.Error(err))
		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	refreshTokenHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		s.Logger.Info("auth.CheckCodeHandler: hash refresh token failed", zap.Error(err))
		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = s.PgRepo.UpdateTokenHash(ctx, userId, refreshTokenHash)
	if err != nil {
		s.Logger.Info(fmt.Sprintf("auth.CheckCodeHandler: update refresh token failed, for user id: %s", userId), zap.Error(err))
		if err.Error() == "user not found" {
			sendErrorResponse(ctx, "User not found", http.StatusNotFound)
			return
		}

		sendErrorResponse(ctx, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := models.CheckCodeResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	sendSuccessResponse(ctx, resp, http.StatusOK)
}
