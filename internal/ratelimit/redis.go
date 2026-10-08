package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/openwaap/openwaap/internal/config"
)

const maxWindow = 365 * 24 * time.Hour

const redisDialTimeout = 3 * time.Second

var slidingWindowScript = redis.NewScript(`
local key   = KEYS[1]
local window = tonumber(ARGV[1])
local now   = tonumber(ARGV[2])
local member = ARGV[3]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
redis.call('ZADD', key, now, member)
return redis.call('ZCOUNT', key, now - window, '+inf')
`)

type RedisBackend struct {
	client redis.Cmdable
	prefix string
}

func NewRedisBackend(client redis.Cmdable, prefix string) *RedisBackend {
	return &RedisBackend{client: client, prefix: prefix}
}

func NewRedisBackendFromConfig(cfg config.RedisConfig) (*RedisBackend, *redis.Client, error) {
	c := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	b := NewRedisBackend(c, cfg.Prefix)
	ctx, cancel := context.WithTimeout(context.Background(), redisDialTimeout)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("redis: ping %s: %w", cfg.Address, err)
	}
	return b, c, nil
}

func (b *RedisBackend) Observe(ctx context.Context, ruleKey string, window time.Duration, now time.Time) (int, error) {
	key := b.prefix + "ratelimit:" + ruleKey
	n := int64(now.UnixNano())
	w := int64(window)
	if window <= 0 || w > int64(maxWindow) {
		return 0, fmt.Errorf("ratelimit: window %s out of range", window)
	}
	member := fmt.Sprintf("%x-%d-%d", randBytes(6), n, time.Now().UnixNano())
	res, err := slidingWindowScript.Run(ctx, b.client, []string{key}, w, n, member).Result()
	if err != nil {
		return 0, err
	}
	switch v := res.(type) {
	case int64:
		return int(v), nil
	case uint64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("ratelimit: unexpected redis reply %T", res)
	}
}

func randBytes(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (b *RedisBackend) Close() error {
	if closer, ok := b.client.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
