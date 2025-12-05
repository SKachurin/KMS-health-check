package main

import (
    "context"
    "log"

    "github.com/redis/go-redis/v9"

    "github.com/SKachurin/KMS-health-check/internal/config"
    "github.com/SKachurin/KMS-health-check/internal/httpserver"
    "github.com/SKachurin/KMS-health-check/internal/kmsclient"
    "github.com/SKachurin/KMS-health-check/internal/ratelimit"
)

func main() {
    ctx := context.Background()
    cfg := config.Load()

    // Redis -> locker
    opt, err := redis.ParseURL(cfg.RedisURL)
    if err != nil { log.Fatal(err) }
    rdb := redis.NewClient(opt)
    locker := ratelimit.NewLocker(rdb, cfg.LockTTL)

    // ONE AWS KMS
    kms1, err := kmsclient.NewAWS(ctx, cfg.KMS1Region, cfg.KMS1KeyID, cfg.KMS1AccessKey, cfg.KMS1SecretKey, cfg.KMS1URL)
    if err != nil { log.Fatal(err) }

    clients := map[string]kmsclient.Client{
        "kms1": kms1,
    }

    go httpserver.Start(ctx, cfg, locker, clients)
//     health.StartLoop(ctx, cfg, clients)
}