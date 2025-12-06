package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/SKachurin/KMS-health-check/internal/config"
	"github.com/SKachurin/KMS-health-check/internal/httpserver"
	"github.com/SKachurin/KMS-health-check/internal/kmsclient"
	"github.com/SKachurin/KMS-health-check/internal/ratelimit"
)

func main() {
	cfg := config.Load()

	// ratelimit.New returns (*Locker, error) — handle both
	locker, err := ratelimit.New(cfg.RedisURL, cfg.LockTTL, 0)
	if err != nil {
		log.Fatalf("ratelimit init: %v", err)
	}

	// Build KMS clients (use your existing helper; or construct manually if you prefer)
	clients, err := kmsclient.BuildAll(cfg)
	if err != nil {
		log.Fatalf("kms clients: %v", err)
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start servers (8443 mTLS + 8080 live)
	httpserver.Start(ctx, cfg, locker, clients)
}