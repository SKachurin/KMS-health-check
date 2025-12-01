package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// --- KMS #1 (AWS) ---
	KMS1URL       string // optional override endpoint, e.g. "kms.eu-north-1.amazonaws.com"
	KMS1Region    string // e.g. "eu-north-1"
	KMS1KeyID     string // e.g. "alias/Platform_key_1"
	KMS1AccessKey string
	KMS1SecretKey string

	// --- Main app callbacks / status (if you use them) ---
	MainStatusURL string

	// --- Security (HMAC with main app) ---
	HealthSecret string // shared HMAC secret for gateway auth

	// --- Redis ---
	RedisURL string // e.g. "redis://redis:6379/0"

	// --- Timing knobs ---
	HealthInterval time.Duration
	ReqTimeout     time.Duration
	Skew           time.Duration // max allowed timestamp skew for HMAC headers
	NonceTTL       time.Duration // replay window for nonces
	LockTTL        time.Duration // deny window for unwrap (user_id, answer_fp)
}

func Load() Config {
	return Config{
		// KMS #1 (AWS)
		KMS1URL:       os.Getenv("KMS1_URL"),
		KMS1Region:    getenv("KMS1_REGION", "eu-north-1"),
		KMS1KeyID:     os.Getenv("KMS1_KEY_ID"),
		KMS1AccessKey: os.Getenv("KMS1_ACCESS_KEY_ID"),
		KMS1SecretKey: os.Getenv("KMS1_SECRET_ACCESS_KEY"),

		// Main app status callback (optional)
		MainStatusURL: os.Getenv("MAIN_STATUS_URL"),

		// Security
		HealthSecret: os.Getenv("KMS_HEALTH_SECRET"),

		// Redis
		RedisURL: os.Getenv("REDIS_URL"),

		// Timing (accept ms like "1500" or Go durations like "2s", "5m")
		HealthInterval: d(os.Getenv("HEALTH_INTERVAL"), 15*time.Second),
		ReqTimeout:     d(os.Getenv("REQ_TIMEOUT"), 2*time.Second),
		Skew:           d(os.Getenv("SIG_SKEW"), 60*time.Second),
		NonceTTL:       d(os.Getenv("NONCE_TTL"), 5*time.Minute),
		LockTTL:        d(os.Getenv("LOCK_TTL"), 5*time.Minute),
	}
}

// d parses a duration from env. Accepts either an integer (milliseconds) or a Go duration string.
func d(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if ms, err := strconv.Atoi(s); err == nil {
		return time.Duration(ms) * time.Millisecond
	}
	if dur, err := time.ParseDuration(s); err == nil {
		return dur
	}
	return def
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}