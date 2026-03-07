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

	// kms3
	c3, err := buildSlot(context.Background(), "kms3", cfg.KMS3Provider, cfg)
	if err != nil {
		return nil, fmt.Errorf("kms3: %w", err)
	}
	if c3 != nil {
		clients["kms3"] = c3
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
		// Slot 1 supports AWS
		if p != "AWS" {
			return nil, nil
		}

		// Require creds
		if cfg.KMS1Region == "" || cfg.KMS1KeyID == "" || cfg.KMS1AccessKey == "" || cfg.KMS1SecretKey == "" {
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
		// Slot 2 supports AZURE
		if p != "AZURE" {
			return nil, nil
		}

		// Require creds
		if cfg.KMS2URL == "" || cfg.KMS2KeyID == "" || cfg.KMS2TenantID == "" || cfg.KMS2ClientID == "" || cfg.KMS2SecretKey == "" {
			return nil, nil
		}

		return NewAzure(
			ctx,
			cfg.KMS2URL,        // vault URL
			cfg.KMS2KeyID,      // key name
			cfg.KMS2TenantID,
			cfg.KMS2ClientID,  // client_id
			cfg.KMS2SecretKey,  // client_secret
		)

    	case "kms3":
    		// Slot 3 supports ORACLE
    		if p != "ORACLE" && p != "OCI" {
    			return nil, nil
    		}

    		if cfg.KMS3CryptoEndpoint == "" ||
                    cfg.KMS3KeyID == "" ||
                    cfg.KMS3UserOCID == "" ||
                    cfg.KMS3TenancyOCID == "" ||
                    cfg.KMS3Fingerprint == "" ||
                    cfg.KMS3Region == "" ||
                    cfg.KMS3PrivateKey == "" {
                    return nil, nil
            }

            return NewOracle(
                ctx,
                cfg.KMS3CryptoEndpoint,
                cfg.KMS3KeyID,
                cfg.KMS3TenancyOCID,
                cfg.KMS3UserOCID,
                cfg.KMS3Region,
                cfg.KMS3Fingerprint,
                cfg.KMS3PrivateKey,
            )

	default:
		return nil, errors.New("unknown slot: " + slot)
	}
}