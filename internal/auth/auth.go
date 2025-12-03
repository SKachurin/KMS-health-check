package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

type Inputs struct {
	BodyCanonical []byte // canonical JSON bytes (no spaces, fixed order)
	Timestamp     time.Time
	Nonce         string
	Secret        []byte
	Skew          time.Duration
}

// Compute HMAC-SHA256(body || "." || ts || "." || nonce)
func ComputeMAC(body []byte, ts string, nonce string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(body)
	h.Write([]byte(".")); h.Write([]byte(ts))
	h.Write([]byte(".")); h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}

func VerifyMAC(givenHex string, body []byte, ts string, nonce string, secret []byte, now time.Time, skew time.Duration) error {
	// check ts freshness
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil { return errors.New("bad ts") }
	if parsed.After(now.Add(skew)) || parsed.Before(now.Add(-skew)) { return errors.New("stale ts") }

    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(ts))
    mac.Write([]byte("\n"))
    mac.Write([]byte(nonce))
    mac.Write([]byte("\n"))
    mac.Write(rawBody)
    want := mac.Sum(nil)

    got, err := hex.DecodeString(sigHex)
    if err != nil { return errors.New("bad sig hex") }
    if !hmac.Equal(got, want) {
        return errors.New("sig mismatch")
    }
    return nil
}