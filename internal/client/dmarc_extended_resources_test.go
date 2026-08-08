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

func TestManagedDMARCDelegatedDomainLifecycle(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/delegated-domains":
			var request struct {
				Items []string `json:"items"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(request.Items, []string{"domain-1"}) {
				t.Fatalf("items = %#v", request.Items)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "domain-1", "domain": "example.invalid", "hash": "abc123"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/delegated-domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{
				"id": "domain-1", "domain": "example.invalid", "dmarcDelegationStatus": "pending", "dkimDelegationStatus": "not-setup", "spfDelegationStatus": "pending",
			}}, "meta": map[string]any{}})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/delegated-domains":
			if got := r.URL.Query().Get("id"); got != "domain-1" {
				t.Fatalf("delete id = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	created, err := apiClient.CreateManagedDMARCDelegatedDomain(ctx, "domain-1")
	if err != nil || created.ID != "domain-1" {
		t.Fatalf("created = %#v, err = %v", created, err)
	}
	read, err := apiClient.GetManagedDMARCDelegatedDomain(ctx, created.ID)
	if err != nil || read.DMARCDelegationStatus != "pending" {
		t.Fatalf("read = %#v, err = %v", read, err)
	}
	if err := apiClient.DeleteManagedDMARCDelegatedDomain(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCDomainGroupAssociationLifecycle(t *testing.T) {
	ctx := context.Background()
	associated := false
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/domain-groups/group-1/association":
			if got := r.URL.Query().Get("domainId"); got != "domain-1" {
				t.Fatalf("add domainId = %q", got)
			}
			associated = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/domain-groups/group-1":
			included := []any{}
			if associated {
				included = append(included, map[string]any{"id": "domain-1", "domain": "example.invalid"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "group-1", "name": "Terraform", "type": "static", "includedDomains": included})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/domain-groups/group-1/association":
			if got := r.URL.Query().Get("domainId"); got != "domain-1" {
				t.Fatalf("remove domainId = %q", got)
			}
			associated = false
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	if err := apiClient.AddManagedDMARCDomainGroupAssociation(ctx, "group-1", "domain-1"); err != nil {
		t.Fatal(err)
	}
	association, err := apiClient.GetManagedDMARCDomainGroupAssociation(ctx, "group-1", "domain-1")
	if err != nil || association.Domain != "example.invalid" {
		t.Fatalf("association = %#v, err = %v", association, err)
	}
	if err := apiClient.RemoveManagedDMARCDomainGroupAssociation(ctx, "group-1", "domain-1"); err != nil {
		t.Fatal(err)
	}
	_, err = apiClient.GetManagedDMARCDomainGroupAssociation(ctx, "group-1", "domain-1")
	if !IsNotFound(err) {
		t.Fatalf("post-delete read error = %v, want not found", err)
	}
}

func TestManagedDMARCDefinitionLifecycle(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		path := "/dmarc-analyzer/v1/delegated-domains/domain-1/dmarc"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == path:
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request["dmarcPolicyPresetId"] != "preset-1" {
				t.Fatalf("preset ID = %q", request["dmarcPolicyPresetId"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodGet && r.URL.Path == path:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"definition": map[string]any{"version": "DMARC1", "policy": "reject", "ruaAddresses": []string{"z@example.invalid", "a@example.invalid"}},
				"record":     map[string]any{"host": "_dmarc", "name": "_dmarc.example.invalid", "value": "redirect.invalid", "type": "CNAME", "ttl": 86400, "published": true},
			})
		case r.Method == http.MethodDelete && r.URL.Path == path:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	if err := apiClient.CreateManagedDMARCDefinition(ctx, "domain-1", "preset-1"); err != nil {
		t.Fatal(err)
	}
	definition, err := apiClient.GetManagedDMARCDefinition(ctx, "domain-1")
	if err != nil {
		t.Fatal(err)
	}
	if definition.Definition.RUAAddresses == nil || (*definition.Definition.RUAAddresses)[0] != "a@example.invalid" {
		t.Fatalf("RUA addresses = %#v", definition.Definition.RUAAddresses)
	}
	if definition.Record.TTL.Value == nil || *definition.Record.TTL.Value != 86400 {
		t.Fatalf("record TTL = %#v", definition.Record.TTL.Value)
	}
	if err := apiClient.DeleteManagedDMARCDefinition(ctx, "domain-1"); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCDKIMDefinitionLifecycle(t *testing.T) {
	ctx := context.Background()
	definitionPath := "/dmarc-analyzer/v1/delegated-domains/domain-1/dkim/selector-1"
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/delegated-domains/domain-1/dkim":
			var request ManagedDMARCDKIMDefinition
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Selector != "selector-1" || request.PublicKey == nil || request.PublicKey.Type != "rsa" {
				t.Fatalf("create request = %#v", request)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(request)
		case r.Method == http.MethodGet && r.URL.Path == definitionPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"selector": "selector-1", "recordType": "txt", "version": "DKIM1", "publicKey": map[string]any{"type": "rsa", "data": "public-key"}, "notes": "updated"})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/delegated-domains/domain-1/dkim/details":
			_ = json.NewEncoder(w).Encode(map[string]any{"record": map[string]any{"name": "_domainkey.example.invalid", "value": []string{"z.ns.invalid", "a.ns.invalid"}, "type": "NS", "ttl": 300}, "published": true})
		case r.Method == http.MethodPut && r.URL.Path == definitionPath:
			var request ManagedDMARCDKIMDefinition
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Notes != "updated" {
				t.Fatalf("notes = %q", request.Notes)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodDelete && r.URL.Path == definitionPath:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	request := ManagedDMARCDKIMDefinition{Selector: "selector-1", RecordType: "txt", Version: "DKIM1", PublicKey: &DMARCDKIMPublicKey{Type: "rsa", Data: "public-key"}}
	if err := apiClient.CreateManagedDMARCDKIMDefinition(ctx, "domain-1", request); err != nil {
		t.Fatal(err)
	}
	definition, err := apiClient.GetManagedDMARCDKIMDefinition(ctx, "domain-1", "selector-1")
	if err != nil || definition.Notes != "updated" {
		t.Fatalf("definition = %#v, err = %v", definition, err)
	}
	details, err := apiClient.GetManagedDMARCDKIMDelegationDetails(ctx, "domain-1")
	if err != nil || details.Record.Values[0] != "a.ns.invalid" {
		t.Fatalf("details = %#v, err = %v", details, err)
	}
	request.Notes = "updated"
	if err := apiClient.UpdateManagedDMARCDKIMDefinition(ctx, "domain-1", "selector-1", request); err != nil {
		t.Fatal(err)
	}
	if err := apiClient.DeleteManagedDMARCDKIMDefinition(ctx, "domain-1", "selector-1"); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCSPFDefinitionLifecycle(t *testing.T) {
	ctx := context.Background()
	spfPath := "/dmarc-analyzer/v1/delegated-domains/domain-1/spf"
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == spfPath:
			var request ManagedDMARCSPFDefinition
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Version != "v=spf1" || request.AllQualifier != "-all" || len(request.Terms) != 1 {
				t.Fatalf("SPF request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodGet && r.URL.Path == spfPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"definition": map[string]any{"version": "v=spf1", "allQualifier": "-all", "terms": []any{map[string]any{"type": "include", "target": "_spf.example.invalid"}}}})
		case r.Method == http.MethodGet && r.URL.Path == spfPath+"/details":
			_ = json.NewEncoder(w).Encode(map[string]any{"definition": map[string]any{"record": map[string]any{"name": "example.invalid", "value": "v=spf1 redirect=x", "type": "TXT", "ttl": "86400"}, "published": true, "normalized": "v=spf1 include:x -all", "compressed": "v=spf1 ip4:192.0.2.0/24 -all"}})
		case r.Method == http.MethodDelete && r.URL.Path == spfPath:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	request := ManagedDMARCSPFDefinition{Version: "v=spf1", AllQualifier: "-all", Terms: []ManagedDMARCSPFTerm{{Type: "include", Target: "_spf.example.invalid"}}}
	if err := apiClient.PutManagedDMARCSPFDefinition(ctx, "domain-1", request); err != nil {
		t.Fatal(err)
	}
	definition, err := apiClient.GetManagedDMARCSPFDefinition(ctx, "domain-1")
	if err != nil || len(definition.Terms) != 1 {
		t.Fatalf("definition = %#v, err = %v", definition, err)
	}
	details, err := apiClient.GetManagedDMARCSPFDetails(ctx, "domain-1")
	if err != nil || details.Definition.Record.TTL.Value == nil || *details.Definition.Record.TTL.Value != 86400 {
		t.Fatalf("details = %#v, err = %v", details, err)
	}
	if err := apiClient.DeleteManagedDMARCSPFDefinition(ctx, "domain-1"); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDMARCVendorsListPaginates(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/dmarc-analyzer/v1/sources/vendors" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("pageToken") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "z", "name": "Z"}}, "meta": map[string]any{"nextPage": "next"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "a", "name": "A"}}, "meta": map[string]any{}})
	})
	vendors, err := apiClient.ListManagedDMARCVendors(ctx)
	if err != nil || len(vendors) != 2 || vendors[0].ID != "a" {
		t.Fatalf("vendors = %#v, err = %v", vendors, err)
	}
}

func TestManagedDMARCUserLifecycle(t *testing.T) {
	ctx := context.Background()
	permission := "limited"
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dmarc-analyzer/v1/users":
			var request ManagedDMARCUserRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.UserEmail != "user@example.invalid" || request.AllowedGroups == nil || (*request.AllowedGroups)[0] != "group-a" {
				t.Fatalf("create request = %#v", request)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "user-1", "userEmail": request.UserEmail})
		case r.Method == http.MethodGet && r.URL.Path == "/dmarc-analyzer/v1/users/user-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "user-1", "userName": "Terraform", "userEmail": "user@example.invalid", "userPermission": permission, "allowedGroups": []any{map[string]any{"id": "group-z"}, map[string]any{"id": "group-a"}}, "features": map[string]any{"dnsChecker": true}})
		case r.Method == http.MethodPut && r.URL.Path == "/dmarc-analyzer/v1/users/user-1":
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if _, exists := request["userEmail"]; exists {
				t.Fatal("update request included immutable userEmail")
			}
			permission, _ = request["userPermission"].(string)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "user-1", "userEmail": "user@example.invalid"})
		case r.Method == http.MethodDelete && r.URL.Path == "/dmarc-analyzer/v1/users/user-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	groups := []string{"group-z", "group-a"}
	created, err := apiClient.CreateManagedDMARCUser(ctx, ManagedDMARCUserRequest{UserName: "Terraform", UserEmail: "user@example.invalid", UserPermission: "limited", AllowedGroups: &groups})
	if err != nil || created.ID != "user-1" {
		t.Fatalf("created = %#v, err = %v", created, err)
	}
	user, err := apiClient.GetManagedDMARCUser(ctx, created.ID)
	if err != nil || user.AllowedGroups[0].ID != "group-a" {
		t.Fatalf("user = %#v, err = %v", user, err)
	}
	if err := apiClient.UpdateManagedDMARCUser(ctx, created.ID, ManagedDMARCUserRequest{UserEmail: "must-not-be-sent@example.invalid", UserPermission: "full"}); err != nil {
		t.Fatal(err)
	}
	user, err = apiClient.GetManagedDMARCUser(ctx, created.ID)
	if err != nil || user.UserPermission != "full" {
		t.Fatalf("updated user = %#v, err = %v", user, err)
	}
	if err := apiClient.DeleteManagedDMARCUser(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestExtendedDMARCListOperationsPaginate(t *testing.T) {
	ctx := context.Background()
	apiClient, _ := newDMARCResourceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var first, second any
		switch r.URL.Path {
		case "/dmarc-analyzer/v1/delegated-domains":
			first, second = map[string]any{"id": "z", "domain": "z.invalid"}, map[string]any{"id": "a", "domain": "a.invalid"}
		case "/dmarc-analyzer/v1/delegated-domains/domain-1/dkim":
			first, second = map[string]any{"selector": "z", "recordType": "cname"}, map[string]any{"selector": "a", "recordType": "cname"}
		case "/dmarc-analyzer/v1/users":
			first, second = map[string]any{"id": "z", "userEmail": "z@example.invalid"}, map[string]any{"id": "a", "userEmail": "a@example.invalid"}
		default:
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("pageToken") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{first}, "meta": map[string]any{"nextPage": "next"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{second}, "meta": map[string]any{}})
	})
	delegated, err := apiClient.ListManagedDMARCDelegatedDomains(ctx)
	if err != nil || len(delegated) != 2 || delegated[0].ID != "a" {
		t.Fatalf("delegated domains = %#v, err = %v", delegated, err)
	}
	dkim, err := apiClient.ListManagedDMARCDKIMDefinitions(ctx, "domain-1")
	if err != nil || len(dkim) != 2 || dkim[0].Selector != "a" {
		t.Fatalf("DKIM definitions = %#v, err = %v", dkim, err)
	}
	users, err := apiClient.ListManagedDMARCUsers(ctx)
	if err != nil || len(users) != 2 || users[0].ID != "a" {
		t.Fatalf("users = %#v, err = %v", users, err)
	}
}

func TestDMARCTTLToleratesPortalDeclaredObjectShape(t *testing.T) {
	var ttl DMARCTTL
	if err := json.Unmarshal([]byte(`{"unexpected":86400}`), &ttl); err != nil {
		t.Fatal(err)
	}
	if ttl.Value != nil {
		t.Fatalf("TTL value = %#v, want unset for unknown object shape", ttl.Value)
	}
}

func TestExtendedDMARCMutationsAreBlockedInReadOnlyMode(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	apiClient, err := New(Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mutations := []func() error{
		func() error { _, err := apiClient.CreateManagedDMARCDelegatedDomain(ctx, "id"); return err },
		func() error { return apiClient.DeleteManagedDMARCDelegatedDomain(ctx, "id") },
		func() error { return apiClient.AddManagedDMARCDomainGroupAssociation(ctx, "group", "domain") },
		func() error { return apiClient.RemoveManagedDMARCDomainGroupAssociation(ctx, "group", "domain") },
		func() error { return apiClient.CreateManagedDMARCDefinition(ctx, "id", "preset") },
		func() error { return apiClient.DeleteManagedDMARCDefinition(ctx, "id") },
		func() error {
			return apiClient.CreateManagedDMARCDKIMDefinition(ctx, "id", ManagedDMARCDKIMDefinition{})
		},
		func() error {
			return apiClient.UpdateManagedDMARCDKIMDefinition(ctx, "id", "selector", ManagedDMARCDKIMDefinition{})
		},
		func() error { return apiClient.DeleteManagedDMARCDKIMDefinition(ctx, "id", "selector") },
		func() error { return apiClient.PutManagedDMARCSPFDefinition(ctx, "id", ManagedDMARCSPFDefinition{}) },
		func() error { return apiClient.DeleteManagedDMARCSPFDefinition(ctx, "id") },
		func() error { _, err := apiClient.CreateManagedDMARCUser(ctx, ManagedDMARCUserRequest{}); return err },
		func() error { return apiClient.UpdateManagedDMARCUser(ctx, "id", ManagedDMARCUserRequest{}) },
		func() error { return apiClient.DeleteManagedDMARCUser(ctx, "id") },
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
