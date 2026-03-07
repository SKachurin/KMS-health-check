package config

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// --- KMS #1 (AWS) ---
	KMS1Provider  string
	KMS1URL       string
	KMS1Region    string
	KMS1KeyID     string
	KMS1AccessKey string
	KMS1SecretKey string
    // --- KMS #2 (Azure) ---
    KMS2Provider  string
    KMS2URL       string // vault URL
    KMS2KeyID     string // key name
    KMS2TenantID  string
    KMS2ClientID  string // client_id
    KMS2SecretKey string // client_secret
    // KMS #3 (Oracle)
    KMS3Provider       string
    KMS3CryptoEndpoint string
    KMS3KeyID          string
    KMS3UserOCID       string
    KMS3TenancyOCID    string
    KMS3Fingerprint    string
    KMS3Region         string
    KMS3PrivateKey     string
	// --- Main app callbacks / status (optional) ---
	MainStatusURL string
	// --- Redis ---
	RedisURL string
	// --- Timing knobs ---
	HealthInterval time.Duration
	ReqTimeout     time.Duration
	Skew           time.Duration // kept for future use
	NonceTTL       time.Duration // kept for future use
	LockTTL        time.Duration // deny window for unwrap (user_id, answer_fp)
	// --- Health probe content (for wrap/unwrap echo) ---
	HealthProbeDEK      string // plaintext string that will be base64'ed and echoed
	HealthProbeAnswerFP string // answer_fp to bind in context
	HealthProbeUserID   int    // user_id for EncryptionContext
	// --- Network policy ---
	TrustProxy  bool
	AllowedCIDRs []net.IPNet // source IPs allowed to hit /kms/*
}

// Parse and load everything from env.
func Load() Config {
	allowed := parseCIDRs(os.Getenv("ALLOW_IPS"))

	return Config{
		// KMS #1 (AWS)
		KMS1Provider:  os.Getenv("KMS1_PROVIDER"),
		KMS1URL:       os.Getenv("KMS1_URL"),
		KMS1Region:    getenv("KMS1_REGION", "eu-north-1"),
		KMS1KeyID:     os.Getenv("KMS1_KEY_ID"),
		KMS1AccessKey: os.Getenv("KMS1_ACCESS_KEY_ID"),
		KMS1SecretKey: os.Getenv("KMS1_SECRET_ACCESS_KEY"),

        // KMS #2 (Azure)
        KMS2Provider:  os.Getenv("KMS2_PROVIDER"),
        KMS2URL:       os.Getenv("KMS2_URL"),
        KMS2KeyID:     os.Getenv("KMS2_KEY_ID"),
        KMS2TenantID:  os.Getenv("KMS2_TENANT_ID"),
        KMS2ClientID:  os.Getenv("KMS2_ACCESS_KEY_ID"),
        KMS2SecretKey: os.Getenv("KMS2_SECRET_ACCESS_KEY"),

		// KMS #3 (Oracle)
        KMS3Provider:       os.Getenv("KMS3_PROVIDER"),
        KMS3CryptoEndpoint: os.Getenv("KMS3_CRYPTO_ENDPOINT"),
        KMS3KeyID:          os.Getenv("KMS3_KEY_ID"),
        KMS3UserOCID:       os.Getenv("KMS3_USER_OCID"),
        KMS3TenancyOCID:    os.Getenv("KMS3_TENANCY_OCID"),
        KMS3Fingerprint:    os.Getenv("KMS3_FINGERPRINT"),
        KMS3Region:         os.Getenv("KMS3_REGION"),
        KMS3PrivateKey:     os.Getenv("KMS3_PRIVATE_KEY"),

		// Optional
		MainStatusURL: os.Getenv("MAIN_STATUS_URL"),

		// Redis
		RedisURL: os.Getenv("REDIS_URL"),

		// Timing
		HealthInterval: d(os.Getenv("HEALTH_INTERVAL"), 15*time.Second),
		ReqTimeout:     d(os.Getenv("REQ_TIMEOUT"), 2*time.Second),
		Skew:           d(os.Getenv("SIG_SKEW"), 60*time.Second),
		NonceTTL:       d(os.Getenv("NONCE_TTL"), 5*time.Minute),
		LockTTL:        d(os.Getenv("LOCK_TTL"), 5*time.Minute),

		// Health probe content
		HealthProbeDEK:      getenv("HEALTH_PROBE_DEK", "kms-health-echo"),
		HealthProbeAnswerFP: getenv("HEALTH_PROBE_ANSWER_FP", "healthcheck"),
		HealthProbeUserID:   geti("HEALTH_PROBE_USER_ID", 0),

		// Network policy
		TrustProxy:  getb("TRUST_PROXY", false),
		AllowedCIDRs: allowed,
	}
}

func (c Config) IsIPAllowed(ip net.IP) bool {
	// If no CIDRs configured, allow all (you can flip to “deny all” if you prefer).
	if len(c.AllowedCIDRs) == 0 {
		return true
	}
	for _, n := range c.AllowedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDRs(s string) []net.IPNet {
	var out []net.IPNet
	if s == "" {
		return out
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		_, n, err := net.ParseCIDR(part)
		if err == nil && n != nil {
			out = append(out, *n)
		}
	}
	return out
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

func getb(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off":
		return false
	default:
		return def
	}
}