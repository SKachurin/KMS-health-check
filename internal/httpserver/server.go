package httpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/SKachurin/KMS-health-check/internal/config"
	"github.com/SKachurin/KMS-health-check/internal/health"
	"github.com/SKachurin/KMS-health-check/internal/kmsclient"
	"github.com/SKachurin/KMS-health-check/internal/ratelimit"
)

type Server struct {
	cfg    config.Config
	locker *ratelimit.Locker
	kms    map[string]kmsclient.Client
}

// Start listener: :8443 HTTPS with mutual TLS (client cert required) for /kms/*
func Start(ctx context.Context, cfg config.Config, locker *ratelimit.Locker, clients map[string]kmsclient.Client) {
	s := &Server{
		cfg:    cfg,
		kms:    clients,
		locker: locker,
	}

	mux := http.NewServeMux()

	// Health probe (simple liveness; no mTLS required if you expose separately)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Wrap/Unwrap behind mTLS + IP allow-list (no HMAC)
	mux.HandleFunc("/kms/wrap", s.withIPAllowList(s.wrap))
	mux.HandleFunc("/kms/unwrap", s.withIPAllowList(s.unwrap))
	mux.HandleFunc("/kms/health/check", s.withIPAllowList(s.kmsHealthCheck))

	// --- TLS + mTLS on 8443 ---
	cert, err := tls.LoadX509KeyPair("/certs/server.crt", "/certs/server.key")
	if err != nil {
		log.Fatal("load server cert:", err)
	}
	caPEM, err := os.ReadFile("/certs/ca.crt")
	if err != nil {
		log.Fatal("read ca:", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		log.Fatal("append CA failed")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	tlsSrv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	go func() {
		<-ctx.Done()
		_ = tlsSrv.Shutdown(context.Background())
	}()

	log.Println("mTLS listening :8443 (wrap/unwrap)")
	if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// IP allow-list using cfg.AllowedCIDRs (e.g., "185.229.225.151/32")
func (s *Server) withIPAllowList(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			jsonError(w, http.StatusForbidden, "forbidden", map[string]any{"reason": "bad remote addr"})
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !s.cfg.IsIPAllowed(ip) {
			jsonError(w, http.StatusForbidden, "forbidden", map[string]any{"reason": "ip not allowed"})
			return
		}
		next(w, r)
	}
}

// ---------- /kms/wrap ----------
func (s *Server) wrap(w http.ResponseWriter, r *http.Request) {
	raw, in, ok := readJSON[struct {
		UserID   int      `json:"user_id"`
		DekB64   string   `json:"dek_b64"`
		HB64     string   `json:"h_b64"`
		AnswerFP string   `json:"answer_fp"`
		KMSIDs   []string `json:"kms_ids"`
	}](w, r)
	if !ok {
		return
	}
	_ = raw

	ids := in.KMSIDs
	if len(ids) == 0 {
		ids = make([]string, 0, len(s.kms))
		for id := range s.kms {
			ids = append(ids, id)
		}
	}

	type res struct {
		Ok   bool   `json:"ok"`
		WB64 string `json:"w_b64,omitempty"`
	}
	out := map[string]res{}
	type pair struct{ id string; val res }
	ch := make(chan pair, len(ids))

	for _, id := range ids {
		client, ok := s.kms[id]
		if !ok {
			ch <- pair{id, res{Ok: false}}
			continue
		}
		go func(id string, c kmsclient.Client) {
			wB64, err := c.Wrap(r.Context(), in.UserID, in.DekB64, in.HB64, in.AnswerFP)
			if err != nil || wB64 == "" {
				ch <- pair{id, res{Ok: false}}
				return
			}
			ch <- pair{id, res{Ok: true, WB64: wB64}}
		}(id, client)
	}
	for range ids {
		p := <-ch
		out[p.id] = p.val
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
}

// ---------- /kms/unwrap (deny window on (user_id, answer_fp)) ----------
func (s *Server) unwrap(w http.ResponseWriter, r *http.Request) {
	raw, in, ok := readJSON[struct {
		UserID   int      `json:"user_id"`
		HB64     string   `json:"h_b64"`
		AnswerFP string   `json:"answer_fp"`
		WB64     string   `json:"w_b64"`
		KMSIDs   []string `json:"kms_ids"`
	}](w, r)
	if !ok {
		return
	}
	_ = raw

	lockKey := "lock:unwrap:" + strconv.Itoa(in.UserID) + ":" + in.AnswerFP
	if ok, _ := s.locker.TryAcquire(r.Context(), lockKey); !ok {
		retry := int(s.cfg.LockTTL.Seconds())
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		jsonError(w, http.StatusTooManyRequests, "rate_limited", map[string]any{
			"retry_after_seconds": retry,
			"key":                 lockKey,
			"scope":               "user_id+answer_fp",
		})
		return
	}

	ids := in.KMSIDs
	if len(ids) == 0 {
		ids = make([]string, 0, len(s.kms))
		for id := range s.kms {
			ids = append(ids, id)
		}
	}

	type pr struct{ id string; ok bool; dek string }
	ch := make(chan pr, len(ids))

	for _, id := range ids {
		client, ok := s.kms[id]
		if !ok {
			ch <- pr{id, false, ""}
			continue
		}
		go func(id string, c kmsclient.Client) {
			dek, ok, err := c.Unwrap(r.Context(), in.UserID, in.HB64, in.AnswerFP, in.WB64)
			if err != nil {
				ch <- pr{id, false, ""}
				return
			}
			ch <- pr{id, ok, dek}
		}(id, client)
	}

	var dekOut string
	results := map[string]map[string]bool{}
	for range ids {
		p := <-ch
		results[p.id] = map[string]bool{"ok": p.ok}
		if dekOut == "" && p.ok && p.dek != "" {
			if _, err := base64.StdEncoding.DecodeString(p.dek); err == nil {
				dekOut = p.dek
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"dek_b64": dekOut,
		"results": results,
	})
}

// /kms/health/check — real echo (wrap+unwrap) using health.CheckOnce
func (s *Server) kmsHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ReqTimeout)
	defer cancel()

	statuses := health.CheckOnce(ctx, s.cfg, s.kms)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"statuses": statuses,
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// helpers

func jsonError(w http.ResponseWriter, code int, msg string, extra map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	out := map[string]any{"error": msg}
	for k, v := range extra {
		out[k] = v
	}
	_ = json.NewEncoder(w).Encode(out)
}

func readJSON[T any](w http.ResponseWriter, r *http.Request) ([]byte, T, bool) {
	var zero T
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "read body failed"})
		return nil, zero, false
	}
	defer r.Body.Close()
	var in T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "invalid JSON"})
		return nil, zero, false
	}
	return raw, in, true
}