package smtp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	gomail "gopkg.in/mail.v2"

	"github.com/LionJr/auth/internal/config"
	"github.com/LionJr/auth/pkg/token_manager"
)

var (
	numbers = [10]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
)

type Smtp struct {
	cfg          config.SMTP
	cacheClient  *redis.Client
	tokenManager *token_manager.TokenManager
}

func NewSmtp(cfg config.SMTP, cacheClient *redis.Client, tokenManager *token_manager.TokenManager) *Smtp {
	return &Smtp{
		cfg:          cfg,
		cacheClient:  cacheClient,
		tokenManager: tokenManager,
	}
}

func generateCode() (string, error) {
	b := make([]byte, 5)
	n, err := io.ReadAtLeast(rand.Reader, b, 5)
	if err != nil {
		return "", err
	}
	if n != 5 {
		return "", errors.New("can't create code")
	}

	for i := 0; i < len(b); i++ {
		b[i] = numbers[int(b[i])%len(numbers)]
	}
	code := string(b)

	return code, nil
}

func (s *Smtp) SendCode(ctx context.Context, receiver, userId string) error {
	code, err := generateCode()
	if err != nil {
		return err
	}

	if err = sendMessage(s.cfg.Username, s.cfg.Password, s.cfg.Host, receiver, "Your one time password", code, s.cfg.Port); err != nil {
		return err
	}

	key := fmt.Sprintf("user_%s", userId)

	val, err := jsoniter.Marshal(code)
	if err != nil {
		return err
	}

	status := s.cacheClient.Set(ctx, key, val, 3*time.Minute)
	if _, err = status.Result(); err != nil {
		return err
	}
	return nil
}

func (s *Smtp) SendNotification(ctx context.Context, receiver, text string) error {
	return sendMessage(
		s.cfg.Username,
		s.cfg.Password,
		s.cfg.Host,
		receiver,
		"Your IP address was changed",
		text,
		s.cfg.Port,
	)
}

func sendMessage(username, password, host, receiver, subject, text string, port int) error {
	message := gomail.NewMessage()
	message.SetHeader("From", username)
	message.SetHeader("To", receiver)
	message.SetHeader("Subject", subject)
	message.SetBody("text/plain", text)

	auth := smtp.PlainAuth("", username, password, host)
	dialer := gomail.NewDialer(host, port, username, password)

	dialer.Auth = auth
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: false, ServerName: dialer.Host}
	dialer.Timeout = 1 * time.Second

	err := dialer.DialAndSend(message)
	return err
}
