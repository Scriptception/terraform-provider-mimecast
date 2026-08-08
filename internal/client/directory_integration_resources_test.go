package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestDirectoryIntegrationCreateRequestBodies(t *testing.T) {
	t.Parallel()

	trueValue := true
	falseValue := false
	port := int64(636)
	info := "directory sync"
	domains := []string{"example.com", "example.org"}
	strict := "strict"
	maxUnlink := "1,000"
	connectorID := "connector-id"
	standard := "standard"

	tests := []struct {
		name     string
		path     string
		expected map[string]any
		call     func(context.Context, *Client) (string, error)
	}{
		{
			name: "active directory",
			path: activeDirectoryIntegrationPath,
			expected: map[string]any{
				"description": "primary", "info": info, "domains": []any{"example.com", "example.org"},
				"hostname": "ad.example.com", "alternateHostname": "ad2.example.com", "port": float64(636),
				"userDn": "CN=sync,DC=example,DC=com", "password": "directory-password", "rootDn": "DC=example,DC=com",
				"encryptionMode": "strict", "acknowledgeDisabledAccounts": true, "enabled": false,
				"maxUnlink": "1,000", "syncContacts": true, "deleteUsers": false,
			},
			call: func(ctx context.Context, c *Client) (string, error) {
				return c.CreateActiveDirectoryIntegration(ctx, ActiveDirectoryIntegrationCreateRequest{
					Description: "primary", Info: &info, Domains: &domains, Hostname: "ad.example.com", AlternateHostname: "ad2.example.com",
					Port: &port, UserDN: "CN=sync,DC=example,DC=com", Password: "directory-password", RootDN: "DC=example,DC=com",
					EncryptionMode: &strict, AcknowledgeDisabledAccounts: &trueValue, Enabled: &falseValue, MaxUnlink: &maxUnlink,
					SyncContacts: &trueValue, DeleteUsers: &falseValue,
				})
			},
		},
		{
			name: "google workspace",
			path: googleDirectoryIntegrationPath,
			expected: map[string]any{
				"enabled": true, "description": "google", "info": info, "domains": []any{"example.com", "example.org"},
				"maxUnlink": "1,000", "deleteUsers": false, "acknowledgeDisabledAccounts": true,
				"user": "sync@example.com", "key": `{"private_key":"private-value"}`,
			},
			call: func(ctx context.Context, c *Client) (string, error) {
				return c.CreateGoogleDirectoryIntegration(ctx, GoogleDirectoryIntegrationCreateRequest{
					Enabled: &trueValue, Description: "google", Info: &info, Domains: &domains, MaxUnlink: &maxUnlink,
					DeleteUsers: &falseValue, AcknowledgeDisabledAccounts: &trueValue, User: "sync@example.com",
					Key: `{"private_key":"private-value"}`,
				})
			},
		},
		{
			name: "microsoft 365",
			path: m365DirectoryIntegrationPath,
			expected: map[string]any{
				"description": "m365", "info": info, "domains": []any{"example.com", "example.org"}, "connectorId": "connector-id",
				"tenantDomain": "tenant.onmicrosoft.com", "serverSubtype": "standard", "syncGuestUsers": true,
				"acknowledgeDisabledAccounts": true, "enabled": false, "maxUnlink": "1,000", "syncContacts": true, "deleteUsers": false,
			},
			call: func(ctx context.Context, c *Client) (string, error) {
				return c.CreateMicrosoft365DirectoryIntegration(ctx, Microsoft365DirectoryIntegrationCreateRequest{
					Description: "m365", Info: &info, Domains: &domains, ConnectorID: &connectorID, TenantDomain: "tenant.onmicrosoft.com",
					ServerSubtype: &standard, SyncGuestUsers: &trueValue, AcknowledgeDisabledAccounts: &trueValue, Enabled: &falseValue,
					MaxUnlink: &maxUnlink, SyncContacts: &trueValue, DeleteUsers: &falseValue,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/oauth/token" {
					tokenFixture(w)
					return
				}
				if request.Method != http.MethodPost || request.URL.Path != test.path {
					t.Fatalf("request = %s %s", request.Method, request.URL.Path)
				}
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(body, test.expected) {
					t.Fatalf("body = %#v, want %#v", body, test.expected)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"integration-id"}`))
			}, nil)
			defer server.Close()

			id, err := test.call(context.Background(), client)
			if err != nil {
				t.Fatal(err)
			}
			if id != "integration-id" {
				t.Fatalf("id = %q", id)
			}
		})
	}
}

func TestDirectoryIntegrationReadResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		body string
		call func(context.Context, *Client) error
	}{
		{
			name: "active directory",
			path: activeDirectoryIntegrationPath + "/integration-id",
			body: `{"enabled":true,"description":"primary","hostname":"ad.example.com","alternateHostname":"ad2.example.com","port":636,"userDn":"CN=sync","rootDn":"DC=example,DC=com","encryptionMode":"strict","status":"ok","lastSyncDateTime":"2026-08-08T00:00:00Z","syncRunning":false,"domains":["example.com"],"acknowledgeDisabledAccounts":true,"maxUnlink":1000,"syncContacts":true,"deleteUsers":false}`,
			call: func(ctx context.Context, c *Client) error {
				out, err := c.GetActiveDirectoryIntegration(ctx, "integration-id")
				if err != nil {
					return err
				}
				if out.ID != "integration-id" || out.MaxUnlink == nil || string(*out.MaxUnlink) != "1,000" || out.Status == nil || *out.Status != "ok" {
					t.Fatalf("response = %#v", out)
				}
				return nil
			},
		},
		{
			name: "google workspace",
			path: googleDirectoryIntegrationPath + "/integration-id",
			body: `{"enabled":true,"description":"google","user":"sync@example.com","lastSyncDateTime":"2026-08-08T00:00:00Z","status":"ok","syncRunning":false,"domains":["example.com"],"acknowledgeDisabledAccounts":true,"maxUnlink":"unlimited","deleteUsers":false}`,
			call: func(ctx context.Context, c *Client) error {
				out, err := c.GetGoogleDirectoryIntegration(ctx, "integration-id")
				if err != nil {
					return err
				}
				if out.ID != "integration-id" || out.User == nil || *out.User != "sync@example.com" || out.MaxUnlink == nil || string(*out.MaxUnlink) != "unlimited" {
					t.Fatalf("response = %#v", out)
				}
				return nil
			},
		},
		{
			name: "microsoft 365",
			path: m365DirectoryIntegrationPath + "/integration-id",
			body: `{"enabled":true,"description":"m365","connectorId":"connector-id","clientId":"client-id","tenantDomain":"tenant.onmicrosoft.com","serverSubtype":"standard","syncGuestUsers":true,"lastSyncDateTime":"2026-08-08T00:00:00Z","syncRunning":false,"domains":["example.com"],"acknowledgeDisabledAccounts":true,"maxUnlink":10,"syncContacts":true,"deleteUsers":false}`,
			call: func(ctx context.Context, c *Client) error {
				out, err := c.GetMicrosoft365DirectoryIntegration(ctx, "integration-id")
				if err != nil {
					return err
				}
				if out.ID != "integration-id" || out.ClientID == nil || *out.ClientID != "client-id" || out.MaxUnlink == nil || string(*out.MaxUnlink) != "10" {
					t.Fatalf("response = %#v", out)
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/oauth/token" {
					tokenFixture(w)
					return
				}
				if request.Method != http.MethodGet || request.URL.Path != test.path {
					t.Fatalf("request = %s %s", request.Method, request.URL.Path)
				}
				_, _ = w.Write([]byte(test.body))
			}, nil)
			defer server.Close()
			if err := test.call(context.Background(), client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryIntegrationUpdateOmitsUnsetSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		expected map[string]any
		call     func(context.Context, *Client) error
	}{
		{
			name:     "active directory",
			path:     activeDirectoryIntegrationPath + "/integration-id",
			expected: map[string]any{"enabled": false},
			call: func(ctx context.Context, c *Client) error {
				enabled := false
				return c.UpdateActiveDirectoryIntegration(ctx, "integration-id", ActiveDirectoryIntegrationUpdateRequest{Enabled: &enabled})
			},
		},
		{
			name:     "google workspace",
			path:     googleDirectoryIntegrationPath + "/integration-id",
			expected: map[string]any{"description": "updated"},
			call: func(ctx context.Context, c *Client) error {
				description := "updated"
				return c.UpdateGoogleDirectoryIntegration(ctx, "integration-id", GoogleDirectoryIntegrationUpdateRequest{Description: &description})
			},
		},
		{
			name:     "microsoft 365",
			path:     m365DirectoryIntegrationPath + "/integration-id",
			expected: map[string]any{"syncGuestUsers": false},
			call: func(ctx context.Context, c *Client) error {
				syncGuestUsers := false
				return c.UpdateMicrosoft365DirectoryIntegration(ctx, "integration-id", Microsoft365DirectoryIntegrationUpdateRequest{SyncGuestUsers: &syncGuestUsers})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/oauth/token" {
					tokenFixture(w)
					return
				}
				if request.Method != http.MethodPatch || request.URL.Path != test.path {
					t.Fatalf("request = %s %s", request.Method, request.URL.Path)
				}
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(body, test.expected) {
					t.Fatalf("body = %#v, want %#v", body, test.expected)
				}
				w.WriteHeader(http.StatusNoContent)
			}, nil)
			defer server.Close()
			if err := test.call(context.Background(), client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryIntegrationDeleteAndNotFound(t *testing.T) {
	t.Parallel()

	deleteCalls := 0
	client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if request.Method == http.MethodDelete {
			deleteCalls++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if request.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"not_found","message":"tenant text must not be exposed"}]}`))
			return
		}
		http.NotFound(w, request)
	}, nil)
	defer server.Close()

	for _, call := range []func(context.Context, *Client) error{
		func(ctx context.Context, c *Client) error { return c.DeleteActiveDirectoryIntegration(ctx, "id") },
		func(ctx context.Context, c *Client) error { return c.DeleteGoogleDirectoryIntegration(ctx, "id") },
		func(ctx context.Context, c *Client) error { return c.DeleteMicrosoft365DirectoryIntegration(ctx, "id") },
	} {
		if err := call(context.Background(), client); err != nil {
			t.Fatal(err)
		}
	}
	if deleteCalls != 3 {
		t.Fatalf("delete calls = %d", deleteCalls)
	}

	_, err := client.GetActiveDirectoryIntegration(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Fatalf("error = %v, want not found", err)
	}
	if strings.Contains(err.Error(), "tenant text") {
		t.Fatalf("error leaked response detail: %v", err)
	}
}

func TestDirectoryIntegrationWritesRespectReadOnly(t *testing.T) {
	t.Parallel()

	requests := 0
	client, server := newFixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}, func(config *Config) { config.ReadOnly = true })
	defer server.Close()

	operations := []func() error{
		func() error {
			_, err := client.CreateActiveDirectoryIntegration(context.Background(), ActiveDirectoryIntegrationCreateRequest{})
			return err
		},
		func() error {
			return client.UpdateGoogleDirectoryIntegration(context.Background(), "id", GoogleDirectoryIntegrationUpdateRequest{})
		},
		func() error { return client.DeleteMicrosoft365DirectoryIntegration(context.Background(), "id") },
	}
	for _, operation := range operations {
		var readOnlyError *ReadOnlyError
		if err := operation(); !errors.As(err, &readOnlyError) {
			t.Fatalf("error = %v, want ReadOnlyError", err)
		}
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want zero", requests)
	}
}

func TestDirectoryIntegrationDiagnosticsRedactSecrets(t *testing.T) {
	t.Parallel()

	const secret = "private-value-must-not-appear"
	client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"code":"invalid_key","message":"` + secret + `","field":"key"}]}`))
	}, nil)
	defer server.Close()

	_, err := client.CreateGoogleDirectoryIntegration(context.Background(), GoogleDirectoryIntegrationCreateRequest{Description: "google", User: "sync@example.com", Key: secret})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", err)
	}
}
