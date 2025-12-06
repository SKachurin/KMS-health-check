package kmsclient

import (
	"context"

	"github.com/SKachurin/KMS-health-check/internal/config"
)

// BuildAll constructs the KMS clients map from env-backed config.
func BuildAll(cfg config.Config) (map[string]Client, error) {
	clients := make(map[string]Client)

	// Accept either blank endpoint (AWS default) or a full URL.
	// If you set KMS1_URL in .env (e.g. "https://kms.eu-north-1.amazonaws.com"),
	// it will be passed through; otherwise leave it "" to let the SDK resolve.
	endpoint := cfg.KMS1URL

	// Only build if creds are present
	if cfg.KMS1Region != "" && cfg.KMS1KeyID != "" &&
		cfg.KMS1AccessKey != "" && cfg.KMS1SecretKey != "" {

		c, err := NewAWS(
			context.Background(),
			cfg.KMS1Region,
			cfg.KMS1KeyID,
			cfg.KMS1AccessKey,
			cfg.KMS1SecretKey,
			endpoint,
		)
		if err != nil {
			return nil, err
		}
		clients["kms1"] = c
	}

	return clients, nil
}