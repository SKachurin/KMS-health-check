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
	KMS1URL       string // e.g. "kms.eu-north-1.amazonaws.com"
	KMS1Region    string // e.g. "eu-north-1"
	KMS1KeyID     string
	KMS1AccessKey string
	KMS1SecretKey string

	// --- Optional status callback (unused by TLS-only flow, keep if you need) ---
	MainStatusURL string

	// --- Redis ---
	RedisURL string // e.g. "redis://redis:6379/0"

	// --- Timing knobs ---
	HealthInterval time.Duration
	ReqTimeout     time.Duration

	// --- Deny window for unwrap (user_id, answer_fp) ---
	LockTTL time.Duration

	// --- IP allow-list for wrap/unwrap (comma-separated CIDRs/IPs) ---
	AllowedCIDRs []string
	allowedNets  []*net.IPNet // parsed at load time
}

func Load() Config {
	c := Config{
		// KMS #1 (AWS)
		KMS1URL:       os.Getenv("KMS1_URL"),
		KMS1Region:    getenv("KMS1_REGION", "eu-north-1"),
		KMS1KeyID:     os.Getenv("KMS1_KEY_ID"),
		KMS1AccessKey: os.Getenv("KMS1_ACCESS_KEY_ID"),
		KMS1SecretKey: os.Getenv("KMS1_SECRET_ACCESS_KEY"),

		// Callback (optional)
		MainStatusURL: os.Getenv("MAIN_STATUS_URL"),

		// Redis
		RedisURL: os.Getenv("REDIS_URL"),

		// Timing
		HealthInterval: d(os.Getenv("HEALTH_INTERVAL"), 15*time.Second),
		ReqTimeout:     d(os.Getenv("REQ_TIMEOUT"), 2*time.Second),

		// Unwrap deny window (default 5m)
		LockTTL: d(os.Getenv("LOCK_TTL"), 5*time.Minute),

		// IP allow-list
		AllowedCIDRs: splitTrim(os.Getenv("ALLOWED_CIDRS")),
	}

	// Parse CIDRs/IPs into nets
	for _, cidr := range c.AllowedCIDRs {
		if cidr == "" {
			continue
		}
		// If user passed a bare IP, treat it as /32 (IPv4) or /128 (IPv6)
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(cidr); ip != nil {
				var mask string
				if ip.To4() != nil {
					mask = "/32"
				} else {
					mask = "/128"
				}
				cidr = cidr + mask
			}
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			c.allowedNets = append(c.allowedNets, n)
		}
	}
	return c
}

func (c Config) IsIPAllowed(ip net.IP) bool {
	// No allow-list => allow all
	if len(c.allowedNets) == 0 {
		return true
	}
	for _, n := range c.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// helpers

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

func splitTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}