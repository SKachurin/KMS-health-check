package kmsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type httpClient struct {
	baseURL string
	http    *http.Client
}

func NewHTTP(baseURL string, timeout time.Duration) Client {
	return &httpClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: timeout},
	}
}

func (c *httpClient) post(ctx context.Context, path string, body any, out any) error {
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("kms %s: %s", path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *httpClient) Health(ctx context.Context) error {
	var r struct{ Ok bool `json:"ok"` }
	err := c.post(ctx, "/health", map[string]string{"payload":"KMS_HEALTH_CHECK"}, &r)
	if err != nil { return err }
	if !r.Ok { return errors.New("kms unhealthy") }
	return nil
}

func (c *httpClient) Wrap(ctx context.Context, userID int, dekB64, hB64, answerFP string) (string, error) {
	var r struct{ WB64 string `json:"w_b64"` }
	err := c.post(ctx, "/wrap", map[string]any{
		"user_id":    userID,
		"dek_b64":    dekB64,
		"h_b64":      hB64,
		"answer_fp":  answerFP,
	}, &r)
	return r.WB64, err
}

func (c *httpClient) Unwrap(ctx context.Context, userID int, hB64, answerFP, wB64 string) (string, bool, error) {
	var resp struct {
		DekB64  string `json:"dek_b64"`
		Ok      bool   `json:"ok"` // if your server returns per-replica ok, keep/ignore as needed
	}
	err := c.post(ctx, "/unwrap", map[string]any{
		"user_id":   userID,
		"h_b64":     hB64,
		"answer_fp": answerFP,
		"w_b64":     wB64,
	}, &resp)
	return resp.DekB64, resp.Ok, err
}
