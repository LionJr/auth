package redis

import (
	"context"

	"github.com/redis/go-redis/v9"

	"test-auth/internal/config"
)

func NewRedisClient(ctx context.Context, cfg config.Redis) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.Db,
	})

	cmd := client.Ping(ctx)
	if _, err := cmd.Result(); err != nil {
		return nil, err
	}

	return client, nil
}
