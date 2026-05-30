package auth

import (
	"crypto/sha512"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"test-auth/internal/models"
)

func sendErrorResponse(ctx *gin.Context, msg string, status int) {
	resp := models.ErrorResponse{
		Message: msg,
	}

	ctx.JSON(status, resp)
}

func sendSuccessResponse(ctx *gin.Context, data interface{}, status int) {
	ctx.JSON(status, data)
}

func hashRefreshToken(refreshToken string) (string, error) {
	hashedToken := prepareTokenHash(refreshToken)
	hash, err := bcrypt.GenerateFromPassword(hashedToken, bcrypt.MinCost)
	return string(hash), err
}

func verifyRefreshToken(hashedToken, enteredToken string) error {
	enteredTokenHash := prepareTokenHash(enteredToken)
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), enteredTokenHash)
}

func prepareTokenHash(token string) []byte {
	newHasher := sha512.New()
	newHasher.Write([]byte(token))
	tokenHash := newHasher.Sum(nil)
	return tokenHash
}
