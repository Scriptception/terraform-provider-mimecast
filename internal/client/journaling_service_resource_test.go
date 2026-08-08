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

func TestJournalingServiceCreateRequestBodies(t *testing.T) {
	t.Parallel()

	trueValue := true
	falseValue := false
	messageFormat := "exchange_env"
	ipRanges := []string{"192.0.2.0/24"}
	deliveryWaitAttempts := int64(3)
	inactivityTimeout := int64(180)
	processInitialDelay := int64(0)
	pop3Port := int64(995)
	smtpPassword := "smtp-password"

	tests := []struct {
		name     string
		request  JournalingServiceCreateRequest
		expected map[string]any
	}{
		{
			name: "smtp",
			request: JournalingServiceCreateRequest{
				Description: "smtp journal", Enabled: &trueValue, MessageFormat: &messageFormat, RemoveJournalHeaders: &falseValue,
				JournalNonInternalAddresses: &trueValue, JournalUnknownInternalAddresses: &falseValue,
				SMTPJournalingConnection: &SMTPJournalingConnectionCreate{
					EmailAddress: "journal@example.com", IPRanges: &ipRanges, UsesAuthentication: &trueValue, Password: &smtpPassword,
					UsesTLS: &trueValue, PrefersClearText: &falseValue, ExtendedDeduplication: &trueValue,
					DeliveryWaitAttempts: &deliveryWaitAttempts, InactivityTimeout: &inactivityTimeout, ProcessInitialDelay: &processInitialDelay,
				},
			},
			expected: map[string]any{
				"description": "smtp journal", "enabled": true, "messageFormat": "exchange_env", "removeJournalHeaders": false,
				"journalNonInternalAddresses": true, "journalUnknownInternalAddresses": false,
				"smtpJournalingConnection": map[string]any{
					"emailAddress": "journal@example.com", "ipRanges": []any{"192.0.2.0/24"}, "usesAuthentication": true,
					"password": "smtp-password", "usesTls": true, "prefersClearText": false, "extendedDeduplication": true,
					"deliveryWaitAttempts": float64(3), "inactivityTimeout": float64(180), "processInitialDelay": float64(0),
				},
			},
		},
		{
			name: "pop3",
			request: JournalingServiceCreateRequest{
				Description: "pop3 journal",
				POP3JournalingConnection: &POP3JournalingConnectionCreate{
					EmailAddress: "journal@example.com", Mailbox: "journal-mailbox", Password: "pop3-password", Host: "pop.example.com",
					Port: &pop3Port, UsesPOP3S: &trueValue, EncryptionIsRelaxed: &falseValue, DetailedLoggingIsEnabled: &trueValue,
				},
			},
			expected: map[string]any{
				"description": "pop3 journal",
				"pop3JournalingConnection": map[string]any{
					"emailAddress": "journal@example.com", "mailbox": "journal-mailbox", "password": "pop3-password", "host": "pop.example.com",
					"port": float64(995), "usesPOP3S": true, "encryptionIsRelaxed": false, "detailedLoggingIsEnabled": true,
				},
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
				if request.Method != http.MethodPost || request.URL.Path != journalingServicesPath {
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
				_, _ = w.Write([]byte(`{"id":"journal-id"}`))
			}, nil)
			defer server.Close()

			id, err := client.CreateJournalingServiceResource(context.Background(), test.request)
			if err != nil {
				t.Fatal(err)
			}
			if id != "journal-id" {
				t.Fatalf("id = %q", id)
			}
		})
	}
}

func TestJournalingServiceUpdateUsesDocumentedPatchNames(t *testing.T) {
	t.Parallel()

	trueValue := true
	falseValue := false
	password := "rotated-password"
	port := int64(110)
	client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if request.Method != http.MethodPatch || request.URL.Path != journalingServicesPath+"/journal-id" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		expected := map[string]any{
			"enabled": false,
			"smtpJournalingConnection": map[string]any{
				"useAuthentication": true, "password": "rotated-password", "useTls": true, "preferClearText": false,
			},
			"pop3JournalingConnection": map[string]any{
				"port": float64(110), "usePop3": false, "relaxedEncryption": true, "detailedLogging": false,
			},
		}
		if !reflect.DeepEqual(body, expected) {
			t.Fatalf("body = %#v, want %#v", body, expected)
		}
		w.WriteHeader(http.StatusNoContent)
	}, nil)
	defer server.Close()

	err := client.UpdateJournalingServiceResource(context.Background(), "journal-id", JournalingServiceUpdateRequest{
		Enabled: &falseValue,
		SMTPJournalingConnection: &SMTPJournalingConnectionUpdate{
			UseAuthentication: &trueValue, Password: &password, UseTLS: &trueValue, PreferClearText: &falseValue,
		},
		POP3JournalingConnection: &POP3JournalingConnectionUpdate{
			Port: &port, UsePOP3: &falseValue, RelaxedEncryption: &trueValue, DetailedLogging: &falseValue,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestJournalingServiceReadDropsReturnedPasswords(t *testing.T) {
	t.Parallel()

	const returnedSecret = "server-returned-password"
	client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != journalingServicesPath+"/journal-id" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"id":"journal-id","description":"journal","messageFormat":"exchange_env","queueSize":4,"transferProtocol":"smtp","enabled":true,
			"smtpJournalingConnection":{"emailAddress":"journal@example.com","password":"` + returnedSecret + `","usesAuthentication":true,"usesTls":true,"hostnames":["journal.example"]},
			"pop3JournalingConnection":{"emailAddress":"mailbox@example.com","mailbox":"mailbox","password":"` + returnedSecret + `","host":"pop.example.com","port":995,"usesPOP3S":true},
			"statusInfo":{"lastReceivedDateTime":"2026-08-08T00:00:00Z","status":"ok"}
		}`))
	}, nil)
	defer server.Close()

	out, err := client.GetJournalingServiceResource(context.Background(), "journal-id")
	if err != nil {
		t.Fatal(err)
	}
	if out.ID == nil || *out.ID != "journal-id" || out.QueueSize == nil || *out.QueueSize != 4 || out.StatusInfo == nil || out.StatusInfo.Status == nil || *out.StatusInfo.Status != "ok" {
		t.Fatalf("response = %#v", out)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), returnedSecret) || strings.Contains(string(encoded), "password") {
		t.Fatalf("safe response retained a password field: %s", encoded)
	}
}

func TestJournalingServiceDeleteAndNotFound(t *testing.T) {
	t.Parallel()

	deleted := false
	client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch request.Method {
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"not_found","message":"not found"}]}`))
		default:
			http.NotFound(w, request)
		}
	}, nil)
	defer server.Close()

	if err := client.DeleteJournalingServiceResource(context.Background(), "journal-id"); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("delete was not sent")
	}
	_, err := client.GetJournalingServiceResource(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Fatalf("error = %v, want not found", err)
	}
}

func TestJournalingServiceWritesRespectReadOnly(t *testing.T) {
	t.Parallel()

	requests := 0
	client, server := newFixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}, func(config *Config) { config.ReadOnly = true })
	defer server.Close()

	operations := []func() error{
		func() error {
			_, err := client.CreateJournalingServiceResource(context.Background(), JournalingServiceCreateRequest{})
			return err
		},
		func() error {
			return client.UpdateJournalingServiceResource(context.Background(), "id", JournalingServiceUpdateRequest{})
		},
		func() error { return client.DeleteJournalingServiceResource(context.Background(), "id") },
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

func TestJournalingServiceDiagnosticsRedactPasswords(t *testing.T) {
	t.Parallel()

	const secret = "journal-password-must-not-appear"
	client, server := newFixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"code":"invalid_password","message":"` + secret + `","field":"password"}]}`))
	}, nil)
	defer server.Close()

	_, err := client.CreateJournalingServiceResource(context.Background(), JournalingServiceCreateRequest{
		Description: "journal",
		POP3JournalingConnection: &POP3JournalingConnectionCreate{
			EmailAddress: "journal@example.com", Mailbox: "mailbox", Password: secret, Host: "pop.example.com",
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked password: %v", err)
	}
}
