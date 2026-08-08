package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientTokenAndRequest(t *testing.T) {
	var tokenRequests int
	var apiRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.Form.Get("client_id"); got != "id" {
				t.Fatalf("client_id = %q", got)
			}
			if got := r.Form.Get("client_secret"); got != "secret" {
				t.Fatalf("client_secret = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
		case "/identity/whoami":
			apiRequests++
			if got := r.Header.Get("Authorization"); got != "Bearer tok" {
				t.Fatalf("Authorization = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "account"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("tokenRequests = %d, want cached single request", tokenRequests)
	}
	if apiRequests != 2 {
		t.Fatalf("apiRequests = %d", apiRequests)
	}
}

func TestParseRateLimitDelayUsesMimecastMilliseconds(t *testing.T) {
	header := http.Header{}
	header.Set("X-RateLimit-Reset", "1750")
	if got := parseRateLimitDelay(header); got != 1750*time.Millisecond {
		t.Fatalf("parseRateLimitDelay = %s, want 1.75s", got)
	}
	header.Set("Retry-After", "2")
	if got := parseRateLimitDelay(header); got != 2*time.Second {
		t.Fatalf("Retry-After precedence = %s, want 2s", got)
	}
	header.Del("Retry-After")
	header.Set("X-RateLimit-Reset", "999999999")
	if got := parseRateLimitDelay(header); got != maxRetryDelay {
		t.Fatalf("bounded delay = %s, want %s", got, maxRetryDelay)
	}
}

func TestClientRetries429(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
			return
		}
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errors":[{"code":"rate_limited","message":"try again"}]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestClientMaxRetriesZeroDisablesRetries(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
			return
		}
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"code":"rate_limited","message":"try again"}]}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestClientRefreshesTokenOnceOn401(t *testing.T) {
	var tokenRequests int
	var apiRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok" + string(rune('0'+tokenRequests)), "expires_in": 3600})
		case "/identity/whoami":
			apiRequests++
			if got := r.Header.Get("Authorization"); got == "Bearer tok1" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"errors":[{"code":"unauthorized","message":"expired"}]}`))
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer tok2" {
				t.Fatalf("Authorization = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "account"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 2 {
		t.Fatalf("tokenRequests = %d, want 2", tokenRequests)
	}
	if apiRequests != 2 {
		t.Fatalf("apiRequests = %d, want 2", apiRequests)
	}
}

func TestClientTreatsLegacyFailEnvelopeAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
			return
		}
		_, _ = w.Write([]byte(`{"fail":[{"errors":[{"code":"invalid","message":"bad request","field":"domain"}]}]}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out)
	if err == nil {
		t.Fatal("expected legacy fail envelope error")
	}
	if !strings.Contains(err.Error(), "Mimecast error invalid for field domain") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestParseErrorMessage(t *testing.T) {
	got := parseErrorMessage([]byte(`{"errors":[{"code":"bad","message":"invalid","field":"domain"}]}`))
	if got != "Mimecast error bad for field domain" {
		t.Fatalf("parseErrorMessage = %q", got)
	}
}
