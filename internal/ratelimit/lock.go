package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Locker struct {
	rdb    *redis.Client
	ttl    time.Duration
	jitter time.Duration
}

func New(redisURL string, ttl, jitter time.Duration) (*Locker, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	rdb := redis.NewClient(opt)

	// quick connectivity check
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Locker{rdb: rdb, ttl: ttl, jitter: jitter}, nil
}

// Deny if key already exists; otherwise set a lock with TTL.
// Keep fail-closed: if Redis errors, return (false, err).
func (l *Locker) TryAcquire(ctx context.Context, key string) (bool, error) {
	exists, err := l.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis EXISTS %q: %w", key, err)
	}
	if exists > 0 {
		return false, nil
	}
	ok, err := l.rdb.SetNX(ctx, key, "1", l.ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis SETNX %q: %w", key, err)
	}
	return ok, nil
}

// Not required for your “fixed TTL” policy, but handy for tests.
func (l *Locker) Release(ctx context.Context, key string) error {
	_, err := l.rdb.Del(ctx, key).Result()
	return err
}