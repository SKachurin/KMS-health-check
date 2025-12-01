package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SKachurin/KMS-health-check/internal/auth"
	"github.com/SKachurin/KMS-health-check/internal/config"
	"github.com/SKachurin/KMS-health-check/internal/kmsclient"
)

func StartLoop(ctx context.Context, cfg config.Config, clients map[string]kmsclient.Client) {
	t := time.NewTicker(cfg.HealthInterval)
	defer t.Stop()
	httpc := &http.Client{Timeout: cfg.ReqTimeout}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			statuses := make(map[string]string, len(clients))
			for id, c := range clients {
				if err := c.Health(ctx); err != nil {
					statuses[id] = "down"
				} else {
					statuses[id] = "up"
				}
			}
			if cfg.MainStatusURL != "" {
				_ = post(ctx, httpc, cfg, statuses)
			}
		}
	}
}

func post(ctx context.Context, httpc *http.Client, cfg config.Config, statuses map[string]string) error {
	body, _ := json.Marshal(map[string]any{"statuses": statuses})
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := randNonce(16)
	sig := auth.ComputeMAC(body, ts, nonce, []byte(cfg.HealthSecret))

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.MainStatusURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ts", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Sig", sig)

	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post status: %s", resp.Status)
	}
	return nil
}

func randNonce(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// fallback: timestamp hex (last resort)
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(b)
}