package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// ComputeMAC builds HMAC-SHA256 over: ts + "\n" + nonce + "\n" + rawBody
func ComputeMAC(rawBody []byte, ts, nonce string, secret []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("\n"))
	m.Write([]byte(nonce))
	m.Write([]byte("\n"))
	m.Write(rawBody)
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyMAC checks the same scheme and enforces timestamp freshness (RFC3339Nano).
func VerifyMAC(sigHex string, rawBody []byte, ts, nonce string, secret []byte, now time.Time, skew time.Duration) error {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return errors.New("bad ts")
	}
	dt := now.Sub(t)
	if dt > skew || dt < -skew {
		return errors.New("ts skew")
	}

	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("\n"))
	m.Write([]byte(nonce))
	m.Write([]byte("\n"))
	m.Write(rawBody)
	want := m.Sum(nil)

	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("bad sig hex")
	}
	if !hmac.Equal(got, want) {
		return errors.New("sig mismatch")
	}
	return nil
}