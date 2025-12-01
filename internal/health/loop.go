package health

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/SKachurin/KMS-health-check/internal/auth"
	"github.com/SKachurin/KMS-health-check/internal/config"
	"github.com/SKachurin/KMS-health-check/internal/kmsclient"
)

func StartLoop(ctx context.Context, cfg config.Config, clients map[string]kmsclient.Client) {
	t := time.NewTicker(cfg.HealthInterval); defer t.Stop()
	httpc := &http.Client{Timeout: cfg.ReqTimeout}

	for {
		select {
		case <-ctx.Done(): return
		case <-t.C:
			statuses := map[string]string{}
			for id, c := range clients {
				if err := c.Health(ctx); err != nil { statuses[id] = "down" } else { statuses[id] = "up" }
			}
			_ = post(ctx, httpc, cfg, statuses)
		}
	}
}

func post(ctx context.Context, httpc *http.Client, cfg config.Config, statuses map[string]string) error {
	body, _ := json.Marshal(map[string]any{
		"statuses": statuses,
	})
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := hexTsNonce()
	sig := auth.ComputeMAC(body, ts, nonce, []byte(cfg.HealthSecret))

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.MainStatusURL, bytes.NewReader(body))
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("X-Ts", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Sig", sig)
	_, err := httpc.Do(req)
	if err != nil { return err }
	return nil
}

func hexTsNonce() string {
	return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
}