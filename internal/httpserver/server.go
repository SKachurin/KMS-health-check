package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/SKachurin/KMS-health-check/internal/auth"
	"github.com/SKachurin/KMS-health-check/internal/config"
	"github.com/SKachurin/KMS-health-check/internal/kmsclient"
	"github.com/SKachurin/KMS-health-check/internal/ratelimit"
)

type Server struct {
	cfg    config.Config
	locker *ratelimit.Locker
	kms    map[string]kmsclient.Client
	secret []byte
}

func Start(ctx context.Context, cfg config.Config, locker *ratelimit.Locker, clients map[string]kmsclient.Client) {
	s := &Server{
		cfg:    cfg,
		kms:    clients,
		locker: locker,
		secret: []byte(cfg.HealthSecret),
	}

	mux := http.NewServeMux()

	// liveness probe
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/kms/wrap", s.withAuth(s.wrap))
	mux.HandleFunc("/kms/unwrap", s.withAuth(s.unwrap))

	srv := &http.Server{Addr: ":8080", Handler: mux}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	log.Println("gateway listening :8080")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts := r.Header.Get("X-Ts")
		nonce := r.Header.Get("X-Nonce")
		sig := r.Header.Get("X-Sig")
		if ts == "" || nonce == "" || sig == "" {
			jsonError(w, http.StatusUnauthorized, "auth_headers_missing", nil)
			return
		}

		// Read raw body exactly as sent, then restore it for the next handler.
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "read body error"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))

		// Verify HMAC over (ts "\n" nonce "\n" rawBody)
		if err := auth.VerifyMAC(sig, raw, ts, nonce, s.secret, time.Now(), s.cfg.Skew); err != nil {
			jsonError(w, http.StatusForbidden, "bad_signature", map[string]any{"reason": err.Error()})
			return
		}

		// one-time nonce (anti-replay)
		if ok, _ := s.locker.TryAcquire(r.Context(), "seen:"+nonce); !ok {
			jsonError(w, http.StatusForbidden, "replay_detected", nil)
			return
		}

		next(w, r)
	}
}

// /kms/wrap — fan out to requested KMS ids (no deny window here)
func (s *Server) wrap(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID   int      `json:"user_id"`
		DekB64   string   `json:"dek_b64"`
		HB64     string   `json:"h_b64"`
		AnswerFP string   `json:"answer_fp"`
		KMSIDs   []string `json:"kms_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "invalid JSON body"})
		return
	}

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

// /kms/unwrap — apply deny window on (user_id, answer_fp)
func (s *Server) unwrap(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID   int      `json:"user_id"`
		HB64     string   `json:"h_b64"`
		AnswerFP string   `json:"answer_fp"`
		WB64     string   `json:"w_b64"`
		KMSIDs   []string `json:"kms_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "invalid JSON body"})
		return
	}

	// TTL-based deny window (e.g., 5m) keyed by (user_id, answer_fp)
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
			// sanity: must be valid base64 before returning
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

func jsonError(w http.ResponseWriter, code int, msg string, extra map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	out := map[string]any{"error": msg}
	for k, v := range extra {
		out[k] = v
	}
	_ = json.NewEncoder(w).Encode(out)
}
