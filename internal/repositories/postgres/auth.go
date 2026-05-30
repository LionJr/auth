package postgres

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
)

type AuthRepository struct {
	db *sqlx.DB
}

func NewAuthRepository(db *sqlx.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

func (a *AuthRepository) GetUserIdByEmail(ctx context.Context, email string) (string, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT id 
                             FROM users WHERE email = $1)`
	err := a.db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return "", err
	}

	var id string
	if !exists {
		query = "INSERT INTO users(email, token_hash) VALUES($1, $2) RETURNING id"
		err = a.db.QueryRowContext(ctx, query, email, "empty token hash").Scan(&id)
	} else {
		query = "SELECT id FROM users WHERE email = $1"
		err = a.db.QueryRowContext(ctx, query, email).Scan(&id)
	}

	return id, err
}

func (a *AuthRepository) UpdateTokenHash(ctx context.Context, userId, tokenHash string) error {
	var exists bool
	query := `SELECT EXISTS (SELECT id 
                             FROM users WHERE id = $1)`
	err := a.db.QueryRowContext(ctx, query, userId).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		return errors.New("user not found")
	}

	query = `UPDATE users SET token_hash = $1 WHERE id = $2`
	_, err = a.db.ExecContext(ctx, query, tokenHash, userId)
	return err
}

func (a *AuthRepository) GetEmailByUserId(ctx context.Context, userId string) (string, error) {
	var email string
	query := "SELECT email FROM users WHERE id = $1"
	err := a.db.QueryRowContext(ctx, query, userId).Scan(&email)
	return email, err
}

func (a *AuthRepository) GetRefreshTokenHashByUserId(ctx context.Context, userId string) (string, error) {
	var tokenHash string
	query := "SELECT token_hash FROM users WHERE id = $1"
	err := a.db.QueryRowContext(ctx, query, userId).Scan(&tokenHash)

	return tokenHash, err
}
