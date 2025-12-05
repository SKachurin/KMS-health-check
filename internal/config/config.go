package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// --- KMS #1 (AWS) ---
	KMS1URL       string
	KMS1Region    string
	KMS1KeyID     string
	KMS1AccessKey string
	KMS1SecretKey string

	// --- Main app callbacks / status (optional) ---
	MainStatusURL string

	// --- Redis ---
	RedisURL string

	// --- Timing knobs ---
	HealthInterval time.Duration
	ReqTimeout     time.Duration
	Skew           time.Duration // unused now; kept for future
	NonceTTL       time.Duration // unused now; kept for future
	LockTTL        time.Duration // deny window for unwrap (user_id, answer_fp)

	// --- Health probe content (for wrap/unwrap echo) ---
	HealthProbeDEK      string // plaintext DEK to echo (base64-encoded internally)
	HealthProbeAnswerFP string // answer_fp used in EncryptionContext
	HealthProbeUserID   int    // user_id used in EncryptionContext
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

		// Redis
		RedisURL: os.Getenv("REDIS_URL"),

		// Timing
		HealthInterval: d(os.Getenv("HEALTH_INTERVAL"), 15*time.Second),
		ReqTimeout:     d(os.Getenv("REQ_TIMEOUT"), 2*time.Second),
		Skew:           d(os.Getenv("SIG_SKEW"), 60*time.Second),
		NonceTTL:       d(os.Getenv("NONCE_TTL"), 5*time.Minute),
		LockTTL:        d(os.Getenv("LOCK_TTL"), 5*time.Minute),

		// Probe content (defaults are safe)
		HealthProbeDEK:      getenv("HEALTH_PROBE_DEK", "kms-health-echo"),
		HealthProbeAnswerFP: getenv("HEALTH_PROBE_ANSWER_FP", "healthcheck"),
		HealthProbeUserID:   geti("HEALTH_PROBE_USER_ID", 0),
	}
}

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

func geti(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}