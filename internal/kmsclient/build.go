package kmsclient

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/SKachurin/KMS-health-check/internal/config"
)

// BuildAll constructs the KMS clients map from env-backed config.
func BuildAll(cfg config.Config) (map[string]Client, error) {
	clients := make(map[string]Client)

	// kms1
	c1, err := buildSlot(context.Background(), "kms1", cfg.KMS1Provider, cfg)
	if err != nil {
		return nil, fmt.Errorf("kms1: %w", err)
	}
	if c1 != nil {
		clients["kms1"] = c1
	}

	// kms2
	c2, err := buildSlot(context.Background(), "kms2", cfg.KMS2Provider, cfg)
	if err != nil {
		return nil, fmt.Errorf("kms2: %w", err)
	}
	if c2 != nil {
		clients["kms2"] = c2
	}

	return clients, nil
}

// buildSlot builds one client ("kms1" / "kms2") based on provider + cfg.
func buildSlot(ctx context.Context, slot string, provider string, cfg config.Config) (Client, error) {
	p := strings.ToUpper(strings.TrimSpace(provider))
	if p == "" {
		return nil, nil
	}

	switch slot {
	case "kms1":
		// Slot 1 supports AWS in your scheme
		if p != "AWS" {
			return nil, nil
		}

		// Require creds
		if cfg.KMS1Region == "" || cfg.KMS1KeyID == "" || cfg.KMS1AccessKey == "" || cfg.KMS1SecretKey == "" {
			// You can return an error instead if you want to fail fast:
			// return nil, errors.New("missing required AWS env vars for kms1")
			return nil, nil
		}

		// Pass through endpoint (empty => AWS default resolver)
		endpoint := strings.TrimSpace(cfg.KMS1URL)

		return NewAWS(
			ctx,
			cfg.KMS1Region,
			cfg.KMS1KeyID,
			cfg.KMS1AccessKey,
			cfg.KMS1SecretKey,
			endpoint,
		)

	case "kms2":
		// Slot 2 supports AZURE in your scheme
		if p != "AZURE" {
			return nil, nil
		}

		// Require creds
		if cfg.KMS2URL == "" || cfg.KMS2KeyID == "" || cfg.KMS2TenantID == "" || cfg.KMS2AccessKey == "" || cfg.KMS2SecretKey == "" {
			// Same choice: skip silently or error out
			// return nil, errors.New("missing required Azure env vars for kms2")
			return nil, nil
		}

		return NewAzure(
			ctx,
			cfg.KMS2URL,        // vault URL
			cfg.KMS2KeyID,      // key name
			cfg.KMS2TenantID,
			cfg.KMS2AccessKey,  // client_id
			cfg.KMS2SecretKey,  // client_secret
		)

	default:
		return nil, errors.New("unknown slot: " + slot)
	}
}