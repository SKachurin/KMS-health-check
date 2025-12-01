package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Locker struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewLocker(rdb *redis.Client, ttl time.Duration) *Locker { return &Locker{rdb: rdb, ttl: ttl} }

// true = acquired (i.e., not seen in last TTL). false = already locked.
func (l *Locker) TryAcquire(ctx context.Context, key string) (bool, error) {
	ok, err := l.rdb.SetNX(ctx, key, "1", l.ttl).Result()
	return ok, err
}
