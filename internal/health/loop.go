package health

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/SKachurin/KMS-health-check/internal/config"
	"github.com/SKachurin/KMS-health-check/internal/kmsclient"
)

// CheckOnce performs a real echo: wrap -> unwrap -> compare.
// "up" only if the returned dek matches the sent one.
func CheckOnce(ctx context.Context, cfg config.Config, clients map[string]kmsclient.Client) map[string]string {
	statuses := make(map[string]string, len(clients))

	// Build probe payload once.
	dekB64 := base64.StdEncoding.EncodeToString([]byte(cfg.HealthProbeDEK))
	// H is unused by AWS KMS encryption context; any base64 is fine for now.
	hB64 := base64.StdEncoding.EncodeToString([]byte("health-H"))
	answerFP := cfg.HealthProbeAnswerFP
	userID := cfg.HealthProbeUserID

	for id, c := range clients {
		// wrap
		wB64, err := c.Wrap(ctx, userID, dekB64, hB64, answerFP)
		if err != nil || wB64 == "" {
			statuses[id] = "down"
			continue
		}
		// unwrap
		outDekB64, ok, err := c.Unwrap(ctx, userID, hB64, answerFP, wB64)
		if err != nil || !ok {
			statuses[id] = "down"
			continue
		}
		// compare
		if outDekB64 == dekB64 {
			statuses[id] = "up"
		} else {
			statuses[id] = "down"
		}
	}
	return statuses
}

// Optional background pusher.
func StartLoop(ctx context.Context, cfg config.Config, clients map[string]kmsclient.Client) {
	t := time.NewTicker(cfg.HealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = CheckOnce(ctx, cfg, clients)
		}
	}
}