package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newFixtureClient(t *testing.T, handler http.HandlerFunc, config func(*Config)) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	cfg := Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0}
	if config != nil {
		config(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return c, server
}

func tokenFixture(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
}

func TestReadOnlyBlocksMutationBeforeOAuthOrAPIRequest(t *testing.T) {
	requests := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}, func(cfg *Config) { cfg.ReadOnly = true })
	defer server.Close()

	err := c.Do(context.Background(), http.MethodPost, "/policy-management/cloud-gateway/v1/greylisting/policies", nil, map[string]any{"description": "test"}, nil)
	var readOnlyErr *ReadOnlyError
	if !errors.As(err, &readOnlyErr) {
		t.Fatalf("error = %v, want ReadOnlyError", err)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want zero", requests)
	}
}

func TestDoReadRejectsNonAllowlistedPOSTBeforeOAuthOrAPIRequest(t *testing.T) {
	requests := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}, func(cfg *Config) { cfg.ReadOnly = true })
	defer server.Close()

	err := c.DoRead(context.Background(), http.MethodPost, "/api/policy/example/create-policy", nil, map[string]any{}, nil)
	if err == nil || !strings.Contains(err.Error(), "not an allowlisted legacy read operation") {
		t.Fatalf("DoRead() error = %v, want allowlist rejection", err)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want zero", requests)
	}
}

func TestNonIdempotentWriteIsNeverRetried(t *testing.T) {
	attempts := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"code":"rate_limited","message":"not exposed"}]}`))
	}, func(cfg *Config) { cfg.MaxRetries = 4 })
	defer server.Close()

	err := c.Do(context.Background(), http.MethodPost, "/write", nil, map[string]any{"value": true}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want one", attempts)
	}
}

func TestTokenURLDefaultsToResolvedBaseURL(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenRequests++
			tokenFixture(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "account"})
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, ClientID: "id", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("tokenRequests = %d, want one", tokenRequests)
	}
}

func TestNewRejectsRemotePlaintextServiceURLsWithoutLeakingValues(t *testing.T) {
	secret := "diagnostic-secret-marker"
	for _, test := range []struct {
		name   string
		config Config
	}{
		{
			name: "base URL",
			config: Config{
				BaseURL:      "http://service-user:" + secret + "@api.example.test",
				ClientID:     "id",
				ClientSecret: "secret",
			},
		},
		{
			name: "token URL",
			config: Config{
				BaseURL:      "https://api.example.test",
				TokenURL:     "http://service-user:" + secret + "@auth.example.test/oauth/token",
				ClientID:     "id",
				ClientSecret: "secret",
			},
		},
		{
			name: "insecure does not permit plaintext",
			config: Config{
				BaseURL:      "http://service-user:" + secret + "@api.example.test",
				ClientID:     "id",
				ClientSecret: "secret",
				Insecure:     true,
			},
		},
		{
			name: "malformed URL",
			config: Config{
				BaseURL:      "https://[" + secret,
				ClientID:     "id",
				ClientSecret: "secret",
			},
		},
		{
			name: "loopback plaintext through remote proxy",
			config: Config{
				BaseURL:      "http://127.0.0.1:8080",
				TokenURL:     "http://127.0.0.1:8080/oauth/token",
				ProxyURL:     "http://proxy-user:" + secret + "@proxy.example.test:8080",
				ClientID:     "id",
				ClientSecret: "secret",
			},
		},
		{
			name: "hostname does not opt in to loopback plaintext",
			config: Config{
				BaseURL:      "http://localhost:8080",
				ClientID:     "id",
				ClientSecret: "secret",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.config)
			if err == nil {
				t.Fatal("remote plaintext service URL must be rejected")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("service URL error exposed a sensitive value marker")
			}
		})
	}
}

func TestNewAllowsLoopbackHTTPForTests(t *testing.T) {
	_, err := New(Config{
		BaseURL:      "http://127.0.0.1:8080",
		TokenURL:     "http://[::1]:8080/oauth/token",
		ClientID:     "id",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("loopback HTTP must remain available for tests: %v", err)
	}
}

func TestServiceTransportBlocksRemotePlaintextRedirects(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{
			name: "OAuth request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://auth.example.test/oauth/token", http.StatusTemporaryRedirect)
			},
			path: "/identity/whoami",
		},
		{
			name: "bearer request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					tokenFixture(w)
					return
				}
				http.Redirect(w, r, "http://api.example.test/redirected", http.StatusTemporaryRedirect)
			},
			path: "/identity/whoami",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			apiClient, err := New(Config{
				BaseURL:      server.URL,
				TokenURL:     server.URL + "/oauth/token",
				ClientID:     "id",
				ClientSecret: "secret",
				Insecure:     true,
				MaxRetries:   0,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = apiClient.Do(context.Background(), http.MethodGet, test.path, nil, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "blocked non-HTTPS") {
				t.Fatalf("remote plaintext redirect error = %v", err)
			}
		})
	}
}

func TestServiceTransportBlocksUnconfiguredLoopbackRedirects(t *testing.T) {
	const secretMarker = "redirect-secret-marker"
	for _, test := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request, string)
		leaked  func(*http.Request) bool
	}{
		{
			name: "OAuth request",
			handler: func(w http.ResponseWriter, r *http.Request, target string) {
				if r.URL.Path == "/oauth/token" {
					http.Redirect(w, r, target+"/oauth/token", http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			},
			leaked: func(r *http.Request) bool {
				return r.FormValue("client_secret") == secretMarker
			},
		},
		{
			name: "bearer request",
			handler: func(w http.ResponseWriter, r *http.Request, target string) {
				if r.URL.Path == "/oauth/token" {
					tokenFixture(w)
					return
				}
				http.Redirect(w, r, target+"/identity/whoami", http.StatusTemporaryRedirect)
			},
			leaked: func(r *http.Request) bool {
				return r.Header.Get("Authorization") == "Bearer token"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaked := false
			loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				leaked = test.leaked(r)
				http.Error(w, "unexpected request", http.StatusBadRequest)
			}))
			defer loopback.Close()

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				test.handler(w, r, loopback.URL)
			}))
			defer server.Close()
			apiClient, err := New(Config{
				BaseURL:      server.URL,
				TokenURL:     server.URL + "/oauth/token",
				ClientID:     "id",
				ClientSecret: secretMarker,
				Insecure:     true,
				MaxRetries:   0,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = apiClient.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "blocked non-HTTPS") {
				t.Fatalf("unconfigured loopback redirect error = %v", err)
			}
			if leaked {
				t.Fatal("sensitive request data reached an unconfigured loopback origin")
			}
		})
	}
}

func TestServiceTransportRestrictsLoopbackHTTPToConfiguredOrigins(t *testing.T) {
	targetRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		http.Redirect(w, r, target.URL+"/identity/whoami", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	apiClient, err := New(Config{
		BaseURL:      source.URL,
		TokenURL:     source.URL + "/oauth/token",
		ClientID:     "id",
		ClientSecret: "secret",
		MaxRetries:   0,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = apiClient.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "blocked non-HTTPS") {
		t.Fatalf("unconfigured loopback origin error = %v", err)
	}
	if targetRequests != 0 {
		t.Fatalf("target requests = %d, want zero", targetRequests)
	}
}

func TestProxyRoutesOAuthAndAPIWithoutLeakingProxyOrBody(t *testing.T) {
	paths := make([]string, 0, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`tenant-secret-body`))
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("proxy-user", "proxy-secret")
	c, err := New(Config{BaseURL: "http://127.0.0.1:1", ClientID: "id", ClientSecret: "secret", ProxyURL: proxyURL.String(), MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = c.Do(context.Background(), http.MethodGet, "/identity/whoami", nil, nil, &out)
	if err == nil {
		t.Fatal("expected API error")
	}
	for _, forbidden := range []string{"proxy-secret", "proxy-user", "tenant-secret-body", proxyURL.String()} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
	if len(paths) != 2 || paths[0] != "/oauth/token" || paths[1] != "/identity/whoami" {
		t.Fatalf("proxy paths = %#v", paths)
	}
}

func TestManagedURLTokenPagination(t *testing.T) {
	apiRequests := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		apiRequests++
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, found := body["data"]; found {
			t.Fatal("unfiltered managed URL inventory request included data")
		}
		var metadata struct {
			Pagination struct {
				PageToken string `json:"pageToken"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(body["meta"], &metadata); err != nil {
			t.Fatal(err)
		}
		if apiRequests == 1 {
			if metadata.Pagination.PageToken != "" {
				t.Fatal("unexpected first page token")
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"b","url":"b.invalid"}],"meta":{"pagination":{"next":"next-token"}}}`))
			return
		}
		if metadata.Pagination.PageToken != "next-token" {
			t.Fatal("unexpected second page token")
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"a","url":"a.invalid"}],"meta":{"pagination":{}}}`))
	}, nil)
	defer server.Close()

	items, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if apiRequests != 2 || len(items) != 2 || items[0].ID != "a" || items[1].ID != "b" {
		t.Fatalf("requests=%d items=%#v", apiRequests, items)
	}
}

func TestAntiSpoofPolicyListAcceptsDocumentedAndObservedWrappers(t *testing.T) {
	for _, fixture := range []struct {
		name string
		body string
	}{
		{name: "documented definitions", body: `{"definitions":[{"id":"documented"}]}`},
		{name: "observed policies", body: `{"policies":[{"id":"observed"}]}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					tokenFixture(w)
					return
				}
				_, _ = w.Write([]byte(fixture.body))
			}, nil)
			defer server.Close()
			items, err := c.ListPolicies(context.Background(), "anti_spoofing")
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 || items[0].ID == "" {
				t.Fatalf("items = %#v", items)
			}
		})
	}
}

func TestPolicyWriteUsesDirectGroupID(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		from := body["from"].(map[string]any)
		if from["groupId"] != "group-id" {
			t.Fatalf("from.groupId = %#v", from["groupId"])
		}
		if _, exists := from["group"]; exists {
			t.Fatalf("unexpected nested group in write body: %#v", from)
		}
		_, _ = w.Write([]byte(`{"policyId":"policy-id"}`))
	}, nil)
	defer server.Close()
	_, err := c.CreatePolicy(context.Background(), "greylisting", Policy{Description: "test", From: PolicyTarget{Type: "profile_group", GroupID: "group-id"}})
	if err != nil {
		t.Fatal(err)
	}
}
