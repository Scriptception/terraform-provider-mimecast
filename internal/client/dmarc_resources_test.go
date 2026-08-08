package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func newDMARCResourceTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	apiClient, err := New(Config{
		BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0, PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return apiClient, server
}

func TestManagedDMARCDomainLifecycleRequests(t *testing.T) {
	ctx := context.Background()
	activityStatus := "active"
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/domains":
			var request struct {
				Items []string `json:"items"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(request.Items, []string{"example.invalid"}) {
				t.Fatalf("create items = %#v", request.Items)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"domain": "example.invalid", "id": "domain-1"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/domains/domain-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "domain-1", "domain": "example.invalid", "activityStatus": activityStatus,
				"detectedStatus": "active", "status": "onboarding", "isPolicyInherited": false,
				"dnsRecords": map[string]any{"a": []any{
					map[string]any{"domain": "z.example.invalid", "value": "192.0.2.2"},
					map[string]any{"domain": "a.example.invalid", "value": "192.0.2.1"},
				}},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/dmarc-analyzer/v1/domains/domain-1":
			var request struct {
				ActivityStatus string `json:"activityStatus"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			activityStatus = request.ActivityStatus
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/domains":
			if got := r.URL.Query().Get("id"); got != "domain-1" {
				t.Fatalf("delete id = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	id, err := apiClient.CreateManagedDMARCDomain(ctx, "example.invalid")
	if err != nil || id != "domain-1" {
		t.Fatalf("create id = %q, err = %v", id, err)
	}
	domain, err := apiClient.GetManagedDMARCDomain(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := domain.DNSRecords.A[0].Domain; got != "a.example.invalid" {
		t.Fatalf("first normalized A record = %q", got)
	}
	if err := apiClient.UpdateManagedDMARCDomain(ctx, id, "inactive"); err != nil {
		t.Fatal(err)
	}
	domain, err = apiClient.GetManagedDMARCDomain(ctx, id)
	if err != nil || domain.ActivityStatus != "inactive" {
		t.Fatalf("updated activity status = %q, err = %v", domain.ActivityStatus, err)
	}
	if err := apiClient.DeleteManagedDMARCDomain(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCDomainGroupLifecycleRequests(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/domain-groups":
			var request DMARCDomainGroupRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.IncludedDomains == nil || !reflect.DeepEqual(*request.IncludedDomains, []string{"domain-a", "domain-z"}) {
				t.Fatalf("included domains = %#v", request.IncludedDomains)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "group-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/domain-groups/group-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "group-1", "name": "Terraform", "type": "static", "doesAutoIncludeOrgSubdomains": false,
				"includeDomainsWithStatus": "active", "domainsCount": 2,
				"includedDomains":     []any{map[string]any{"id": "domain-z", "domain": "z.invalid"}, map[string]any{"id": "domain-a", "domain": "a.invalid"}},
				"includeDomainsRegex": []string{"z.*", "a.*"},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/dmarc-analyzer/v1/domain-groups/group-1":
			var request DMARCDomainGroupRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Name != "Terraform updated" {
				t.Fatalf("update name = %q", request.Name)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/domain-groups":
			if got := r.URL.Query().Get("id"); got != "group-1" {
				t.Fatalf("delete id = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	included := []string{"domain-z", "domain-a"}
	id, err := apiClient.CreateManagedDMARCDomainGroup(ctx, DMARCDomainGroupRequest{Name: "Terraform", Type: "static", IncludedDomains: &included})
	if err != nil || id != "group-1" {
		t.Fatalf("create id = %q, err = %v", id, err)
	}
	group, err := apiClient.GetManagedDMARCDomainGroup(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := group.IncludedDomains[0].ID; got != "domain-a" {
		t.Fatalf("first normalized included domain = %q", got)
	}
	if got := group.IncludeDomainsRegex[0]; got != "a.*" {
		t.Fatalf("first normalized regex = %q", got)
	}
	if err := apiClient.UpdateManagedDMARCDomainGroup(ctx, id, DMARCDomainGroupRequest{Name: "Terraform updated", Type: "static"}); err != nil {
		t.Fatal(err)
	}
	if err := apiClient.DeleteManagedDMARCDomainGroup(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCNotificationLifecycleRequests(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/notifications/complianceMonitor":
			var request DMARCNotificationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Domains == nil || !reflect.DeepEqual(*request.Domains, []string{"domain-a", "domain-z"}) {
				t.Fatalf("domains = %#v", request.Domains)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "notification-1", "type": "complianceMonitor"})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/notifications/notification-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "notification-1", "type": "complianceMonitor", "email": []string{"z@example.invalid", "a@example.invalid"}, "frequency": "weekly",
				"domains":       []any{map[string]any{"id": "domain-z", "name": "z.invalid"}, map[string]any{"id": "domain-a", "name": "a.invalid"}},
				"triggerConfig": map[string]any{"isIndividualDomainAlert": true, "invalidMessageTrigger": map[string]any{"enabled": true, "threshold": 10, "interval": "daily"}},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/dmarc-analyzer/v1/notifications/notification-1":
			var request DMARCNotificationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Frequency != "monthly" {
				t.Fatalf("frequency = %q", request.Frequency)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/notifications":
			if got := r.URL.Query().Get("ids"); got != "notification-1" {
				t.Fatalf("delete ids = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	domains := []string{"domain-z", "domain-a"}
	created, err := apiClient.CreateManagedDMARCNotification(ctx, "complianceMonitor", DMARCNotificationRequest{
		Emails: []string{"alerts@example.invalid"}, Frequency: "weekly", Domains: &domains,
		TriggerConfig: &DMARCNotificationTriggerConfig{InvalidMessageTrigger: &DMARCComplianceTrigger{}},
	})
	if err != nil || created.ID != "notification-1" {
		t.Fatalf("create id = %q, err = %v", created.ID, err)
	}
	notification, err := apiClient.GetManagedDMARCNotification(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := notification.Emails[0]; got != "a@example.invalid" {
		t.Fatalf("first normalized email = %q", got)
	}
	if got := notification.Domains[0].ID; got != "domain-a" {
		t.Fatalf("first normalized domain = %q", got)
	}
	if err := apiClient.UpdateManagedDMARCNotification(ctx, created.ID, DMARCNotificationRequest{Emails: []string{"alerts@example.invalid"}, Frequency: "monthly"}); err != nil {
		t.Fatal(err)
	}
	if err := apiClient.DeleteManagedDMARCNotification(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCPolicyPresetLifecycleAndPagination(t *testing.T) {
	ctx := context.Background()
	var updateSeen bool
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/dmarc-policy-preset":
			var request DMARCPolicyPresetRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.RUAAddresses == nil || !reflect.DeepEqual(*request.RUAAddresses, []string{"a@example.invalid", "z@example.invalid"}) {
				t.Fatalf("rua addresses = %#v", request.RUAAddresses)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "preset-1", "name": request.Name, "version": "DMARC1", "policy": "none"})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/dmarc-policy-preset":
			if got := r.URL.Query().Get("id"); got != "preset-1" {
				t.Fatalf("preset filter = %q", got)
			}
			if r.URL.Query().Get("pageToken") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "other", "name": "Other", "version": "DMARC1", "policy": "reject"}}, "meta": map[string]any{"nextPage": "next-token"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{
				"id": "preset-1", "name": "Terraform", "version": "DMARC1", "policy": "none", "isDefaultPolicy": false,
				"ruaAddresses": []string{"z@example.invalid", "a@example.invalid"}, "failureReportingOptions": "0:d:s", "percentage": 100,
			}}, "meta": map[string]any{}})
		case r.Method == http.MethodPut && r.URL.Path == "/dmarc-analyzer/v1/dmarc-policy-preset/preset-1":
			var request DMARCPolicyPresetRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			updateSeen = request.Policy == "quarantine"
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/dmarc-policy-preset":
			if got := r.URL.Query().Get("id"); got != "preset-1" {
				t.Fatalf("delete id = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	rua := []string{"z@example.invalid", "a@example.invalid"}
	created, err := apiClient.CreateManagedDMARCPolicyPreset(ctx, DMARCPolicyPresetRequest{
		Name: "Terraform", ManagedDMARCDefinition: ManagedDMARCDefinition{Version: "DMARC1", Policy: "none", RUAAddresses: &rua},
	})
	if err != nil || created.ID != "preset-1" {
		t.Fatalf("create id = %q, err = %v", created.ID, err)
	}
	preset, err := apiClient.GetManagedDMARCPolicyPreset(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preset.RUAAddresses == nil || (*preset.RUAAddresses)[0] != "a@example.invalid" {
		t.Fatalf("normalized rua addresses = %#v", preset.RUAAddresses)
	}
	if preset.FailureReportingOptions != "0:d:s" {
		t.Fatalf("failure reporting options = %q", preset.FailureReportingOptions)
	}
	if err := apiClient.UpdateManagedDMARCPolicyPreset(ctx, created.ID, DMARCPolicyPresetRequest{Name: "Terraform", ManagedDMARCDefinition: ManagedDMARCDefinition{Version: "DMARC1", Policy: "quarantine"}}); err != nil {
		t.Fatal(err)
	}
	if !updateSeen {
		t.Fatal("update request was not observed")
	}
	if err := apiClient.DeleteManagedDMARCPolicyPreset(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCListOperationsPaginateAndSort(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		pageToken := r.URL.Query().Get("pageToken")
		if got := r.URL.Query().Get("pageSize"); got != "2" {
			t.Fatalf("pageSize = %q", got)
		}
		var first, second any
		switch r.URL.Path {
		case "/dmarc-analyzer/v1/domains":
			first, second = map[string]any{"id": "z", "domain": "z.invalid"}, map[string]any{"id": "a", "domain": "a.invalid"}
		case "/dmarc-analyzer/v1/domain-groups":
			first, second = map[string]any{"id": "z", "name": "Z", "type": "static"}, map[string]any{"id": "a", "name": "A", "type": "static"}
		case "/dmarc-analyzer/v1/notifications":
			first, second = map[string]any{"id": "z", "type": "dmarcSummary"}, map[string]any{"id": "a", "type": "dmarcSummary"}
		case "/dmarc-analyzer/v1/dmarc-policy-preset":
			first, second = map[string]any{"id": "z", "name": "Z", "version": "DMARC1", "policy": "none"}, map[string]any{"id": "a", "name": "A", "version": "DMARC1", "policy": "none"}
		default:
			http.NotFound(w, r)
			return
		}
		if pageToken == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{first}, "meta": map[string]any{"nextPage": "next"}})
			return
		}
		if pageToken != "next" {
			t.Fatalf("pageToken = %q", pageToken)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{second}, "meta": map[string]any{}})
	})

	domains, err := apiClient.ListManagedDMARCDomains(ctx)
	if err != nil || domains[0].ID != "a" || len(domains) != 2 {
		t.Fatalf("domains = %#v, err = %v", domains, err)
	}
	groups, err := apiClient.ListManagedDMARCDomainGroups(ctx)
	if err != nil || groups[0].ID != "a" || len(groups) != 2 {
		t.Fatalf("groups = %#v, err = %v", groups, err)
	}
	notifications, err := apiClient.ListManagedDMARCNotifications(ctx)
	if err != nil || notifications[0].ID != "a" || len(notifications) != 2 {
		t.Fatalf("notifications = %#v, err = %v", notifications, err)
	}
	presets, err := apiClient.ListManagedDMARCPolicyPresets(ctx)
	if err != nil || presets[0].ID != "a" || len(presets) != 2 {
		t.Fatalf("presets = %#v, err = %v", presets, err)
	}
}

func TestDMARCResourceMutationsAreBlockedBeforeRequestInReadOnlyMode(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	apiClient, err := New(Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mutations := []func() error{
		func() error { _, err := apiClient.CreateManagedDMARCDomain(ctx, "example.invalid"); return err },
		func() error { return apiClient.UpdateManagedDMARCDomain(ctx, "id", "inactive") },
		func() error { return apiClient.DeleteManagedDMARCDomain(ctx, "id") },
		func() error {
			_, err := apiClient.CreateManagedDMARCDomainGroup(ctx, DMARCDomainGroupRequest{})
			return err
		},
		func() error { return apiClient.UpdateManagedDMARCDomainGroup(ctx, "id", DMARCDomainGroupRequest{}) },
		func() error { return apiClient.DeleteManagedDMARCDomainGroup(ctx, "id") },
		func() error {
			_, err := apiClient.CreateManagedDMARCNotification(ctx, "dmarcSummary", DMARCNotificationRequest{})
			return err
		},
		func() error { return apiClient.UpdateManagedDMARCNotification(ctx, "id", DMARCNotificationRequest{}) },
		func() error { return apiClient.DeleteManagedDMARCNotification(ctx, "id") },
		func() error {
			_, err := apiClient.CreateManagedDMARCPolicyPreset(ctx, DMARCPolicyPresetRequest{})
			return err
		},
		func() error { return apiClient.UpdateManagedDMARCPolicyPreset(ctx, "id", DMARCPolicyPresetRequest{}) },
		func() error { return apiClient.DeleteManagedDMARCPolicyPreset(ctx, "id") },
	}
	for index, mutation := range mutations {
		err := mutation()
		var readOnlyError *ReadOnlyError
		if !errors.As(err, &readOnlyError) {
			t.Fatalf("mutation %d error = %T %v, want ReadOnlyError", index, err, err)
		}
	}
	if requests != 0 {
		t.Fatalf("HTTP requests = %d, want 0", requests)
	}
}
