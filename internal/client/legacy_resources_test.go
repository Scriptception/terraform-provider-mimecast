package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestAddressAlterationSetInventoryIsTypedFlatAndDeterministic(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != addressAlterationSetPath {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var request struct {
			Data []addressAlterationSetFilter `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Data) != 1 || request.Data[0].FolderID != "root" || request.Data[0].Depth != 3 {
			t.Fatalf("unexpected Address Alteration Set filter: %#v", request.Data)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"set-b","description":"B","folderCount":1,"folders":[{"id":"set-a","description":"A","parentId":"set-b"}]},{"id":"set-a","description":"A","parentId":"set-b"}]}`))
	}, nil)
	defer server.Close()

	items, err := c.ListAddressAlterationSets(context.Background(), "root", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "set-a" || items[1].ID != "set-b" {
		t.Fatalf("items = %#v", items)
	}
	if len(items[1].Folders) != 0 {
		t.Fatalf("recursive folders were not flattened: %#v", items[1])
	}
}

func TestAddressAlterationDefinitionLifecycleContract(t *testing.T) {
	getRequests := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		switch r.URL.Path {
		case addressAlterationCreateDefPath:
			var request struct {
				Data []struct {
					FolderID           string                        `json:"folderId"`
					AddressAlterations []AddressAlterationDefinition `json:"addressAlterations"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Data) != 1 || request.Data[0].FolderID != "set-1" || len(request.Data[0].AddressAlterations) != 1 {
				t.Fatalf("unexpected create request: %#v", request)
			}
			definition := request.Data[0].AddressAlterations[0]
			if definition.ID != "" || definition.FolderID != "" || definition.AddressType != "from" || definition.OriginalAddress != "old@example.test" || definition.NewAddress != "new@example.test" || definition.Routing != "inbound" {
				t.Fatalf("unexpected definition request: %#v", definition)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"definition-1","success":true}]}`))
		case addressAlterationGetDefPath:
			getRequests++
			var request struct {
				Data []struct {
					Routing  string `json:"routing"`
					FolderID string `json:"folderId"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Data) != 1 {
				t.Fatalf("unexpected get request: %#v", request)
			}
			if request.Data[0].FolderID == "set-1" {
				_, _ = w.Write([]byte(`{"data":[{"items":[{"id":"definition-1","addressType":"from","originalAddress":"old@example.test","newAddress":"new@example.test","routing":"inbound"}]}]}`))
				return
			}
			if request.Data[0].Routing == "all" || request.Data[0].Routing == "inbound" || request.Data[0].Routing == "outbound" {
				_, _ = w.Write([]byte(`{"data":[{"items":[]}]}`))
				return
			}
			t.Fatalf("unexpected definition filter: %#v", request.Data[0])
		case addressAlterationSetPath:
			_, _ = w.Write([]byte(`{"data":[{"id":"set-1","description":"Rewrite definitions"}]}`))
		case addressAlterationDeleteDefPath:
			assertLegacyIDRequest(t, r, "definition-1")
			_, _ = w.Write([]byte(`{"data":[{"id":"definition-1","success":true}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}, nil)
	defer server.Close()

	definition := AddressAlterationDefinition{FolderID: "set-1", AddressType: "from", OriginalAddress: "old@example.test", NewAddress: "new@example.test", Routing: "inbound"}
	id, err := c.CreateAddressAlterationDefinition(context.Background(), definition)
	if err != nil {
		t.Fatal(err)
	}
	if id != "definition-1" {
		t.Fatalf("id = %q", id)
	}
	read, err := c.GetAddressAlterationDefinition(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if read.ID != id || read.FolderID != "set-1" || read.Routing != "inbound" || getRequests != 4 {
		t.Fatalf("read=%#v getRequests=%d", read, getRequests)
	}
	if err := c.DeleteAddressAlterationDefinition(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func TestAddressAlterationDefinitionRejectsFalsePerItemSuccess(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"definition-1","success":false}]}`))
	}, nil)
	defer server.Close()

	_, err := c.CreateAddressAlterationDefinition(context.Background(), AddressAlterationDefinition{AddressType: "from", OriginalAddress: "old@example.test", NewAddress: "new@example.test", Routing: "all"})
	if err == nil || !strings.Contains(err.Error(), "was not successful") {
		t.Fatalf("error = %v", err)
	}
}

func TestAddressAlterationInventoriesDiscoverIDsAndSort(t *testing.T) {
	definitionFilters := make(map[string]bool)
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch r.URL.Path {
		case addressAlterationSetPath:
			_, _ = w.Write([]byte(`{"data":[{"id":"set-b","description":"B"},{"id":"set-a","description":"A"}]}`))
		case addressAlterationGetDefPath:
			var request struct {
				Data []addressAlterationDefinitionFilter `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Data) != 1 {
				t.Fatalf("definition filter = %#v", request.Data)
			}
			filter := request.Data[0]
			key := "routing:" + filter.Routing
			if filter.FolderID != "" {
				key = "folder:" + filter.FolderID
			}
			definitionFilters[key] = true
			switch key {
			case "routing:inbound":
				_, _ = w.Write([]byte(`{"data":[{"items":[{"id":"definition-root","addressType":"from","originalAddress":"root-old@example.test","newAddress":"root-new@example.test","routing":"inbound"}]}]}`))
			case "folder:set-a":
				_, _ = w.Write([]byte(`{"data":[{"items":[{"id":"definition-a","addressType":"from","originalAddress":"a-old@example.test","newAddress":"a-new@example.test","routing":"all"}]}]}`))
			case "folder:set-b":
				_, _ = w.Write([]byte(`{"data":[{"items":[{"id":"definition-b","addressType":"sender","originalAddress":"b-old@example.test","newAddress":"b-new@example.test","routing":"outbound"}]}]}`))
			default:
				_, _ = w.Write([]byte(`{"data":[{"items":[]}]}`))
			}
		case addressAlterationGetPolicy:
			var request struct {
				Data []map[string]any `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Data) != 1 || len(request.Data[0]) != 0 {
				t.Fatalf("policy inventory must omit id: %#v", request.Data)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"policy-b","addressAlterationSetId":"set-b","policy":{"description":"B","from":{"type":"everyone"},"to":{"type":"everyone"}}},{"id":"policy-a","addressAlterationSetId":"set-a","policy":{"description":"A","from":{"type":"everyone"},"to":{"type":"everyone"}}}]}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, nil)
	defer server.Close()

	definitions, err := c.ListAddressAlterationDefinitions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 3 || definitions[0].ID != "definition-a" || definitions[0].FolderID != "set-a" || definitions[1].ID != "definition-b" || definitions[2].ID != "definition-root" {
		t.Fatalf("definitions = %#v", definitions)
	}
	for _, key := range []string{"routing:all", "routing:inbound", "routing:outbound", "folder:set-a", "folder:set-b"} {
		if !definitionFilters[key] {
			t.Fatalf("definition inventory did not query %s", key)
		}
	}
	policies, err := c.ListAddressAlterationPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies[0].ID != "policy-a" || policies[1].ID != "policy-b" {
		t.Fatalf("policies = %#v", policies)
	}
}

func TestPendingDomainsUsesDocumentedCursorPagination(t *testing.T) {
	pages := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/domain/cloud-gateway/v1/pending-domains" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		pages++
		if r.URL.Query().Get("pageSize") == "" || r.URL.Query().Has("inboundType") || r.URL.Query().Has("local") {
			t.Fatalf("pending-domain query = %s", r.URL.RawQuery)
		}
		if pages == 1 {
			if r.URL.Query().Get("pageToken") != "" {
				t.Fatalf("first page token = %q", r.URL.Query().Get("pageToken"))
			}
			_, _ = w.Write([]byte(`{"domains":[{"id":"domain-z","domain":"z.example.test"}],"meta":{"nextPage":"next"}}`))
			return
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatalf("second page token = %q", r.URL.Query().Get("pageToken"))
		}
		_, _ = w.Write([]byte(`{"domains":[{"id":"domain-a","domain":"a.example.test"}],"meta":{}}`))
	}, nil)
	defer server.Close()

	items, err := c.ListPendingDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "domain-a" || items[1].ID != "domain-z" || pages != 2 {
		t.Fatalf("items=%#v pages=%d", items, pages)
	}
}

func TestJournalingAndConnectorInventoriesKeepTypedPublicFields(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch r.URL.Path {
		case "/journaling/cloud-gateway/v1/services":
			_, _ = w.Write([]byte(`{"journalingServices":[{"id":"journal-1","description":"primary","enabled":true,"messageFormat":"exchange","queueSize":2,"removeJournalHeaders":true,"transferProtocol":"smtp","journalNonInternalAddresses":false,"journalUnknownInternalAddresses":true,"smtpJournalingConnection":{"emailAddress":"journal@example.test","ipRanges":["198.51.100.0/24","192.0.2.0/24"],"usesAuthentication":true,"password":"must-not-decode","usesTls":true,"prefersClearText":false,"extendedDeduplication":true,"deliveryWaitAttempts":3,"inactivityTimeout":180,"processInitialDelay":5,"hostnames":["z.example.test","a.example.test"]},"pop3JournalingConnection":{"emailAddress":"pop@example.test","mailbox":"journal","password":"must-not-decode","host":"pop.example.test","port":995,"usesPOP3S":true,"encryptionIsRelaxed":false,"detailedLoggingIsEnabled":true},"statusInfo":{"lastReceivedDateTime":"2026-08-08T00:00:00Z","status":"healthy"}}],"meta":{}}`))
		case "/connector/cloud-gateway/v1/connectors":
			_, _ = w.Write([]byte(`{"connectors":[{"id":"connector-1","name":"Microsoft 365","description":"tenant connector","product":{"id":"product-1","name":"M365","code":"m365","description":"Microsoft 365 connector"},"provider":"microsoft","status":"connected"}],"meta":{}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, nil)
	defer server.Close()

	services, err := c.ListJournalingServices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].SMTPJournalingConnection == nil || services[0].POP3JournalingConnection == nil || services[0].StatusInfo == nil {
		t.Fatalf("journaling services = %#v", services)
	}
	smtp := services[0].SMTPJournalingConnection
	if smtp.IPRanges == nil || strings.Join(*smtp.IPRanges, ",") != "192.0.2.0/24,198.51.100.0/24" || smtp.Hostnames == nil || strings.Join(*smtp.Hostnames, ",") != "a.example.test,z.example.test" || services[0].StatusInfo.Status == nil || *services[0].StatusInfo.Status != "healthy" {
		t.Fatalf("typed journaling connection/status = %#v / %#v", smtp, services[0].StatusInfo)
	}

	connectors, err := c.ListConnectors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(connectors) != 1 || connectors[0].Product.Description != "Microsoft 365 connector" {
		t.Fatalf("connectors = %#v", connectors)
	}
}

func TestAddressAlterationPolicyLifecycleAndDirectGroupID(t *testing.T) {
	gets := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		switch r.URL.Path {
		case addressAlterationCreatePolicy:
			assertLegacyPolicyWrite(t, r, false)
			_, _ = w.Write([]byte(`{"data":[{"id":"policy-1","addressAlterationSetId":"set-1","policy":{"description":"rewrite"}}]}`))
		case addressAlterationGetPolicy:
			gets++
			assertLegacyIDRequest(t, r, "policy-1")
			_, _ = w.Write([]byte(`{"data":[{"id":"policy-1","addressAlterationSetId":"set-1","policy":{"description":"rewrite","from":{"type":"profile_group","group":{"id":"group-1"}},"to":{"type":"everyone"},"conditions":{"sourceIPs":["10.1.0.0/16","10.0.0.0/8"]}}}]}`))
		case addressAlterationUpdatePolicy:
			assertLegacyPolicyWrite(t, r, true)
			_, _ = w.Write([]byte(`{"data":[{"id":"policy-1"}]}`))
		case addressAlterationDeletePolicy:
			assertLegacyIDRequest(t, r, "policy-1")
			_, _ = w.Write([]byte(`{"data":[{"id":"policy-1","deleted":true}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}, nil)
	defer server.Close()

	policy := testAddressAlterationPolicy()
	id, err := c.CreateAddressAlterationPolicy(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	read, err := c.GetAddressAlterationPolicy(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if read.Policy.From.ResolvedGroupID() != "group-1" || read.Policy.Conditions == nil || strings.Join(read.Policy.Conditions.SourceIPs, ",") != "10.0.0.0/8,10.1.0.0/16" {
		t.Fatalf("read policy = %#v", read)
	}
	if err := c.UpdateAddressAlterationPolicy(context.Background(), id, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAddressAlterationPolicy(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if gets != 2 {
		t.Fatalf("get requests = %d, want 2", gets)
	}
	if err := c.DeleteAddressAlterationPolicy(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func TestWebSecurityURLPolicyLifecycleAndStableCanonicalRead(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		switch r.URL.Path {
		case webSecurityCreatePolicyPath:
			assertWebSecurityWrite(t, r, false)
			_, _ = w.Write([]byte(`{"data":[{"id":"web-1"}]}`))
		case webSecurityGetPolicyPath:
			assertLegacyIDRequest(t, r, "web-1")
			_, _ = w.Write([]byte(`{"data":[{"id":"web-1","description":"web policy","policies":[{"id":"target-b","policy":{"description":"B","from":{"type":"everyone"},"to":{"type":"everyone"}}},{"id":"target-a","policy":{"description":"A","from":{"type":"profile_group","group":{"id":"group-1"}},"to":{"type":"everyone"}}}],"urls":[{"id":"url-b","type":"url","value":"https://b.example.test","action":"block"},{"id":"url-a","type":"domain","value":"a.example.test","action":"allow"}]}]}`))
		case webSecurityUpdatePolicyPath:
			assertWebSecurityWrite(t, r, true)
			_, _ = w.Write([]byte(`{"data":[{"id":"web-1"}]}`))
		case webSecurityDeletePolicyPath:
			assertLegacyIDRequest(t, r, "web-1")
			_, _ = w.Write([]byte(`{"data":[{"id":"web-1","deleted":true}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}, nil)
	defer server.Close()

	policy := testWebSecurityPolicy()
	id, err := c.CreateWebSecurityURLPolicy(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	read, err := c.GetWebSecurityURLPolicy(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Policies) != 2 || read.Policies[0].ID != "target-a" || len(read.URLs) != 2 || read.URLs[0].ID != "url-a" {
		t.Fatalf("canonical read = %#v", read)
	}
	if read.Policies[0].Policy.From.ResolvedGroupID() != "group-1" {
		t.Fatalf("nested read group was not resolved: %#v", read.Policies[0])
	}
	read.Policies = []WebSecurityTargetPolicy{read.Policies[0]}
	read.URLs = []WebSecurityURLAction{read.URLs[0]}
	if err := c.UpdateWebSecurityURLPolicy(context.Background(), id, read); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteWebSecurityURLPolicy(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func TestThreatReportingSubscriptionLifecycleUsesCurrentOpenAPIPath(t *testing.T) {
	gets := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == threatReportingSubscriptions:
			var request threatReportingCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.ClientState != "new-state" || request.NotificationURL != "https://callback.example.test/mimecast" || request.ResourceType != "threat-analysis" {
				t.Fatal("unexpected create subscription request")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"subscriptionId":"subscription-1","expirationDateTime":"2026-08-11T00:00:00Z","resourceType":"threat-analysis"}`))
		case r.Method == http.MethodGet && r.URL.Path == threatReportingSubscriptions:
			gets++
			_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"subscription-2","resourceType":"threat-analysis"},{"subscriptionId":"subscription-1","creationDateTime":"2026-08-08T00:00:00Z","expirationDateTime":"2026-08-11T00:00:00Z","resourceType":"threat-analysis"}]}`))
		case r.Method == http.MethodPatch && r.URL.Path == threatReportingSubscriptions+"/subscription-1":
			var request threatReportingUpdateRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.OldClientState != "old-state" || request.ClientState != "new-state" {
				t.Fatal("unexpected renewal client-state request")
			}
			_, _ = w.Write([]byte(`{"subscriptionId":"subscription-1","expirationDateTime":"2026-08-14T00:00:00Z"}`))
		case r.Method == http.MethodDelete && r.URL.Path == threatReportingSubscriptions+"/subscription-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, nil)
	defer server.Close()

	created, err := c.CreateThreatReportingSubscription(context.Background(), "https://callback.example.test/mimecast", "threat-analysis", "new-state")
	if err != nil {
		t.Fatal(err)
	}
	if created.SubscriptionID != "subscription-1" {
		t.Fatalf("created = %#v", created)
	}
	read, err := c.GetThreatReportingSubscription(context.Background(), created.SubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	if read.SubscriptionID != created.SubscriptionID || gets != 1 {
		t.Fatalf("read=%#v gets=%d", read, gets)
	}
	updated, err := c.UpdateThreatReportingSubscription(context.Background(), created.SubscriptionID, "old-state", "new-state")
	if err != nil {
		t.Fatal(err)
	}
	if updated.SubscriptionID != created.SubscriptionID {
		t.Fatalf("updated = %#v", updated)
	}
	if err := c.DeleteThreatReportingSubscription(context.Background(), created.SubscriptionID); err != nil {
		t.Fatal(err)
	}
}

func TestThreatReportingSubscriptionListAcceptsGuideBareArray(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		_, _ = w.Write([]byte(`[{"subscriptionId":"b"},{"subscriptionId":"a"}]`))
	}, nil)
	defer server.Close()

	items, err := c.ListThreatReportingSubscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].SubscriptionID != "a" || items[1].SubscriptionID != "b" {
		t.Fatalf("items = %#v", items)
	}
}

func TestLegacyMutationIsBlockedBeforeOAuthAndDoesNotLeakWriteOnlyValue(t *testing.T) {
	requests := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}, func(cfg *Config) { cfg.ReadOnly = true })
	defer server.Close()

	err := func() error {
		_, err := c.CreateThreatReportingSubscription(context.Background(), "https://callback.example.test", "threat-analysis", "write-only-state")
		return err
	}()
	var readOnlyErr *ReadOnlyError
	if !errors.As(err, &readOnlyErr) {
		t.Fatalf("error = %v, want ReadOnlyError", err)
	}
	if strings.Contains(err.Error(), "write-only-state") {
		t.Fatal("error exposed write-only client state")
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want zero", requests)
	}
}

func TestExistingGatewayPolicyClientLifecycle(t *testing.T) {
	getCalls := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		const collection = "/policy-management/cloud-gateway/v1/greylisting/policies"
		const object = collection + "/gateway-policy-1"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var request Policy
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Description != "gateway policy" || request.From.GroupID != "group-1" || request.From.Group != nil {
				t.Fatalf("create request = %#v", request)
			}
			_, _ = w.Write([]byte(`{"policyId":"gateway-policy-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == object:
			getCalls++
			_, _ = w.Write([]byte(`{"description":"gateway policy","from":{"type":"profile_group","group":{"id":"group-1"}},"to":{"type":"everyone"}}`))
		case r.Method == http.MethodPatch && r.URL.Path == object:
			var request Policy
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Description != "gateway policy updated" {
				t.Fatalf("update request = %#v", request)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == object:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, nil)
	defer server.Close()

	policy := Policy{Description: "gateway policy", From: PolicyTarget{Type: "profile_group", GroupID: "group-1"}, To: PolicyTarget{Type: "everyone"}}
	id, err := c.CreatePolicy(context.Background(), "greylisting", policy)
	if err != nil || id != "gateway-policy-1" {
		t.Fatalf("id=%q error=%v", id, err)
	}
	read, err := c.GetPolicy(context.Background(), "greylisting", id)
	if err != nil || read.ID != id || read.From.ResolvedGroupID() != "group-1" {
		t.Fatalf("read=%#v error=%v", read, err)
	}
	policy.Description = "gateway policy updated"
	if err := c.UpdatePolicy(context.Background(), "greylisting", id, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPolicy(context.Background(), "greylisting", id); err != nil {
		t.Fatal(err)
	}
	if getCalls != 2 {
		t.Fatalf("get calls = %d, want 2", getCalls)
	}
	if err := c.DeletePolicy(context.Background(), "greylisting", id); err != nil {
		t.Fatal(err)
	}
}

func TestExistingDefinitionClientLifecycles(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/policy-management/cloud-gateway/v1/delivery-route/definitions":
			_, _ = w.Write([]byte(`{"id":"route-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/policy-management/cloud-gateway/v1/delivery-route/definitions/route-1":
			_, _ = w.Write([]byte(`{"id":"route-1","description":"route","hostname":"mail.example.test","port":25}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/policy-management/cloud-gateway/v1/delivery-route/definitions/route-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/policy-management/cloud-gateway/v1/delivery-route/definitions/route-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions":
			_, _ = w.Write([]byte(`{"id":"dns-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions/dns-1":
			_, _ = w.Write([]byte(`{"id":"dns-1","description":"dkim","domain":"example.test","selector":"mimecast"}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions/dns-1":
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request["description"] != "dkim updated" || request["domain"] != nil || request["selector"] != nil {
				t.Fatalf("DNS patch included immutable fields: %#v", request)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions/dns-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, nil)
	defer server.Close()

	route := DeliveryRouteDefinition{Description: "route", Hostname: "mail.example.test", Port: 25}
	routeID, err := c.CreateDeliveryRouteDefinition(context.Background(), route)
	if err != nil || routeID != "route-1" {
		t.Fatalf("route id=%q error=%v", routeID, err)
	}
	if _, err := c.GetDeliveryRouteDefinition(context.Background(), routeID); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateDeliveryRouteDefinition(context.Background(), routeID, route); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDeliveryRouteDefinition(context.Background(), routeID); err != nil {
		t.Fatal(err)
	}

	sign := true
	dns := DNSOutboundDefinition{Description: "dkim", Domain: "example.test", Selector: "mimecast", SignDKIM: &sign}
	dnsID, err := c.CreateDNSOutboundDefinition(context.Background(), dns)
	if err != nil || dnsID != "dns-1" {
		t.Fatalf("DNS id=%q error=%v", dnsID, err)
	}
	if _, err := c.GetDNSOutboundDefinition(context.Background(), dnsID); err != nil {
		t.Fatal(err)
	}
	dns.Description = "dkim updated"
	if err := c.UpdateDNSOutboundDefinition(context.Background(), dnsID, dns); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDNSOutboundDefinition(context.Background(), dnsID); err != nil {
		t.Fatal(err)
	}
}

func TestExistingManagedURLClientLifecycle(t *testing.T) {
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch r.URL.Path {
		case "/api/ttp/url/create-managed-url":
			_, _ = w.Write([]byte(`{"data":[{"id":"url-1"}]}`))
		case "/api/ttp/url/get-all-managed-urls":
			var request struct {
				Data []struct {
					DomainOrURL string `json:"domainOrUrl"`
					ExactMatch  bool   `json:"exactMatch"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Data) != 1 || request.Data[0].DomainOrURL != "example.test" || !request.Data[0].ExactMatch {
				t.Fatalf("managed URL filter = %#v", request)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"url-1","url":"example.test","action":"block"}],"meta":{"pagination":{}}}`))
		case "/api/ttp/url/delete-managed-url":
			assertLegacyIDRequest(t, r, "url-1")
			_, _ = w.Write([]byte(`{"data":[{"id":"url-1","success":true}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}, nil)
	defer server.Close()

	id, err := c.CreateManagedURL(context.Background(), ManagedURL{URL: "example.test", Action: "block"})
	if err != nil || id != "url-1" {
		t.Fatalf("id=%q error=%v", id, err)
	}
	items, err := c.ListManagedURLs(context.Background(), "example.test", true)
	if err != nil || len(items) != 1 || items[0].ID != id {
		t.Fatalf("items=%#v error=%v", items, err)
	}
	if err := c.DeleteManagedURL(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func TestExistingMiscClientLifecyclesAndPagination(t *testing.T) {
	memberPages := 0
	groupGets := 0
	cloudGets := 0
	cloudWrites := 0
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/directory/cloud-gateway/v1/groups":
			_, _ = w.Write([]byte(`{"id":"group-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/directory/cloud-gateway/v1/groups/group-1":
			groupGets++
			_, _ = w.Write([]byte(`{"id":"group-1","description":"group","source":"cloud"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/directory/update-group":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/directory/delete-group":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/directory/cloud-gateway/v1/groups/group-1/members":
			_, _ = w.Write([]byte(`{"results":[{"success":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/directory/cloud-gateway/v1/groups/group-1/members":
			memberPages++
			if memberPages == 1 {
				if r.URL.Query().Get("pageToken") != "" {
					t.Fatalf("first page token = %q", r.URL.Query().Get("pageToken"))
				}
				_, _ = w.Write([]byte(`{"groupMembers":[{"emailAddress":"z@example.test"}],"meta":{"nextPage":"next"}}`))
				return
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatalf("second page token = %q", r.URL.Query().Get("pageToken"))
			}
			_, _ = w.Write([]byte(`{"groupMembers":[{"emailAddress":"a@example.test"}],"meta":{}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/directory/cloud-gateway/v1/groups/group-1/remove-members":
			_, _ = w.Write([]byte(`{"results":[{"success":true}]}`))
		case r.Method == http.MethodPut && r.URL.Path == "/email/cloud-gateway/v1/outbound-ip-addresses":
			var request struct {
				Addresses []string `json:"outboundIpAddresses"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if strings.Join(request.Addresses, ",") != "192.0.2.1,198.51.100.2" {
				t.Fatalf("outbound addresses = %#v", request.Addresses)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/email/cloud-gateway/v1/outbound-ip-addresses":
			_, _ = w.Write([]byte(`{"outboundIpAddresses":["198.51.100.2","192.0.2.1"]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/email/cloud-gateway/v1/outbound-ip-addresses":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/email/cloud-integrated/v1/policies":
			cloudWrites++
			assertCloudIntegratedWrite(t, r)
			_, _ = w.Write([]byte(`{"policyId":"cloud-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/email/cloud-integrated/v1/policies/cloud-1":
			cloudGets++
			_, _ = w.Write([]byte(`{"policyId":"cloud-1","accountId":"account-1","name":"cloud policy","description":"typed policy","protectionMode":"ACTIVE","targets":{"senders":{"route":"ALL","emails":["z@example.test","a@example.test"],"groups":[{"id":"group-z"},{"id":"group-a"}],"domains":["z.example.test","a.example.test"]},"recipients":{"route":"INTERNAL"},"exceptions":{"emails":["exception@example.test"],"groups":[{"id":"group-exception"}],"domains":["exception.example.test"]},"addressMatch":"BOTH"},"actions":{"malware":"BLOCK","phishing":"QUARANTINE","untrustworthy":"MOVE_TO_JUNK","spam":"DO_NOTHING"},"alerts":{"malware":true,"phishing":false,"untrustworthy":true,"spam":false},"securityEngines":{"urlClick":{"sensitivity":"HIGH","scanUrlsInAttachment":true,"rewriteEnabled":true,"rewriteMode":"AGGRESSIVE","forceSecureConnection":true,"blockDangerousExtensions":true,"userIdentification":"ADV_SSO","biUnclassifiedUrls":true,"biAdminViewing":false,"biEnterText":true,"biPasteText":false,"biCopyText":true,"scanOutboundEmails":true},"phishing":{"sensitivityPhishingHigh":90,"sensitivityUntrustworthyHigh":70,"scanOutboundEmails":true},"impersonation":{"codeBreakerStatus":"ENABLED","reportingStatus":"LEARNING","silencerStatus":"DISABLED"},"attachments":{"sandboxEnabled":true,"unreadableArchives":"QUARANTINE"}}}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/email/cloud-integrated/v1/policies/cloud-1":
			cloudWrites++
			assertCloudIntegratedWrite(t, r)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/email/cloud-integrated/v1/policies/cloud-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, nil)
	defer server.Close()

	groupID, err := c.CreateProfileGroup(context.Background(), ProfileGroup{Description: "group"})
	if err != nil || groupID != "group-1" {
		t.Fatalf("group id=%q error=%v", groupID, err)
	}
	if _, err := c.GetProfileGroup(context.Background(), groupID); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateProfileGroup(context.Background(), ProfileGroup{ID: groupID, Description: "group"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetProfileGroup(context.Background(), groupID); err != nil {
		t.Fatal(err)
	}
	member := GroupMember{EmailAddress: "a@example.test"}
	if err := c.AddProfileGroupMembers(context.Background(), groupID, []GroupMember{member}); err != nil {
		t.Fatal(err)
	}
	members, err := c.ListProfileGroupMembers(context.Background(), groupID)
	if err != nil || len(members) != 2 || members[0].EmailAddress != "a@example.test" || memberPages != 2 {
		t.Fatalf("members=%#v pages=%d error=%v", members, memberPages, err)
	}
	if err := c.RemoveProfileGroupMembers(context.Background(), groupID, []GroupMember{member}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteProfileGroup(context.Background(), groupID); err != nil {
		t.Fatal(err)
	}
	if groupGets != 2 {
		t.Fatalf("group gets = %d, want 2", groupGets)
	}

	if err := c.PutOutboundIPAddresses(context.Background(), []string{"198.51.100.2", "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	addresses, err := c.GetOutboundIPAddresses(context.Background())
	if err != nil || strings.Join(addresses, ",") != "192.0.2.1,198.51.100.2" {
		t.Fatalf("addresses=%#v error=%v", addresses, err)
	}
	if err := c.DeleteOutboundIPAddresses(context.Background()); err != nil {
		t.Fatal(err)
	}

	enabled := true
	disabled := false
	phishingSensitivity := int64(90)
	untrustworthySensitivity := int64(70)
	cloud := CloudIntegratedPolicy{
		PolicyID:       "response-policy-id",
		AccountID:      "response-account-id",
		Name:           "cloud policy",
		Description:    "typed policy",
		ProtectionMode: "ACTIVE",
		Targets: &CloudIntegratedTargets{
			Senders: &CloudIntegratedRouteTarget{
				Route:   "ALL",
				Emails:  []string{"z@example.test", "a@example.test"},
				Groups:  []CloudIntegratedGroup{{ID: "group-z"}, {ID: "group-a"}},
				Domains: []string{"z.example.test", "a.example.test"},
			},
			Recipients:   &CloudIntegratedRouteTarget{Route: "INTERNAL"},
			Exceptions:   &CloudIntegratedException{Emails: []string{"exception@example.test"}, Groups: []CloudIntegratedGroup{{ID: "group-exception"}}, Domains: []string{"exception.example.test"}},
			AddressMatch: "BOTH",
		},
		Actions: &CloudIntegratedActions{Malware: "BLOCK", Phishing: "QUARANTINE", Untrustworthy: "MOVE_TO_JUNK", Spam: "DO_NOTHING"},
		Alerts:  &CloudIntegratedAlerts{Malware: &enabled, Phishing: &disabled, Untrustworthy: &enabled, Spam: &disabled},
		SecurityEngines: &CloudIntegratedSecurityEngines{
			URLClick: &CloudIntegratedURLClickEngine{
				Sensitivity: "HIGH", ScanURLsInAttachment: &enabled, RewriteEnabled: &enabled, RewriteMode: "AGGRESSIVE", ForceSecureConnection: &enabled,
				BlockDangerousExtensions: &enabled, UserIdentification: "ADV_SSO", BIUnclassifiedURLs: &enabled, BIAdminViewing: &disabled,
				BIEnterText: &enabled, BIPasteText: &disabled, BICopyText: &enabled, ScanOutboundEmails: &enabled,
			},
			Phishing:      &CloudIntegratedPhishingEngine{SensitivityPhishingHigh: &phishingSensitivity, SensitivityUntrustworthyHigh: &untrustworthySensitivity, ScanOutboundEmails: &enabled},
			Impersonation: &CloudIntegratedImpersonationEngine{CodeBreakerStatus: "ENABLED", ReportingStatus: "LEARNING", SilencerStatus: "DISABLED"},
			Attachments:   &CloudIntegratedAttachmentsEngine{SandboxEnabled: &enabled, UnreadableArchives: "QUARANTINE"},
		},
	}
	cloudID, err := c.CreateCloudIntegratedPolicy(context.Background(), cloud)
	if err != nil || cloudID != "cloud-1" {
		t.Fatalf("cloud id=%q error=%v", cloudID, err)
	}
	readCloud, err := c.GetCloudIntegratedPolicy(context.Background(), cloudID)
	if err != nil {
		t.Fatal(err)
	}
	if readCloud.Targets == nil || readCloud.Targets.Senders == nil || strings.Join(readCloud.Targets.Senders.Emails, ",") != "a@example.test,z@example.test" || readCloud.SecurityEngines == nil || readCloud.SecurityEngines.Phishing == nil || readCloud.SecurityEngines.Phishing.SensitivityPhishingHigh == nil || *readCloud.SecurityEngines.Phishing.SensitivityPhishingHigh != 90 {
		t.Fatalf("typed cloud read = %#v", readCloud)
	}
	if err := c.UpdateCloudIntegratedPolicy(context.Background(), cloudID, cloud); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCloudIntegratedPolicy(context.Background(), cloudID); err != nil {
		t.Fatal(err)
	}
	if cloudGets != 2 {
		t.Fatalf("cloud gets = %d, want 2", cloudGets)
	}
	if cloudWrites != 2 {
		t.Fatalf("cloud writes = %d, want 2", cloudWrites)
	}
	if err := c.DeleteCloudIntegratedPolicy(context.Background(), cloudID); err != nil {
		t.Fatal(err)
	}
}

func assertCloudIntegratedWrite(t *testing.T, r *http.Request) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["policyId"]; exists {
		t.Fatalf("write included response-only policyId: %#v", raw)
	}
	if _, exists := raw["accountId"]; exists {
		t.Fatalf("write included response-only accountId: %#v", raw)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var request CloudIntegratedPolicy
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	if request.Targets == nil || request.Targets.Senders == nil || request.Targets.Senders.Route != "ALL" || strings.Join(request.Targets.Senders.Emails, ",") != "a@example.test,z@example.test" {
		t.Fatalf("typed cloud targets = %#v", request.Targets)
	}
	if len(request.Targets.Senders.Groups) != 2 || request.Targets.Senders.Groups[0].ID != "group-a" || request.Targets.Senders.Groups[1].ID != "group-z" {
		t.Fatalf("typed cloud groups = %#v", request.Targets.Senders.Groups)
	}
	if request.Actions == nil || request.Actions.Untrustworthy != "MOVE_TO_JUNK" || request.Alerts == nil || request.Alerts.Phishing == nil || *request.Alerts.Phishing {
		t.Fatalf("typed cloud actions/alerts = %#v / %#v", request.Actions, request.Alerts)
	}
	if request.SecurityEngines == nil || request.SecurityEngines.URLClick == nil || request.SecurityEngines.URLClick.UserIdentification != "ADV_SSO" || request.SecurityEngines.Attachments == nil || request.SecurityEngines.Attachments.UnreadableArchives != "QUARANTINE" {
		t.Fatalf("typed cloud security engines = %#v", request.SecurityEngines)
	}
}

func assertLegacyIDRequest(t *testing.T, r *http.Request, want string) {
	t.Helper()
	var request struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatal(err)
	}
	if len(request.Data) != 1 || request.Data[0].ID != want {
		t.Fatalf("unexpected ID request: %#v", request)
	}
}

func assertLegacyPolicyWrite(t *testing.T, r *http.Request, update bool) {
	t.Helper()
	var request struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatal(err)
	}
	if len(request.Data) != 1 {
		t.Fatalf("unexpected request data: %#v", request.Data)
	}
	if update && request.Data[0]["id"] != "policy-1" {
		t.Fatalf("update ID = %#v", request.Data[0]["id"])
	}
	policy, ok := request.Data[0]["policy"].(map[string]any)
	if !ok {
		t.Fatalf("policy = %#v", request.Data[0]["policy"])
	}
	from, ok := policy["from"].(map[string]any)
	if !ok || from["groupId"] != "group-1" {
		t.Fatalf("from = %#v", from)
	}
	if _, nested := from["group"]; nested {
		t.Fatalf("write used nested group: %#v", from)
	}
	conditions := policy["conditions"].(map[string]any)
	sourceIPs := conditions["sourceIPs"].([]any)
	if len(sourceIPs) != 2 || sourceIPs[0] != "10.0.0.0/8" || sourceIPs[1] != "10.1.0.0/16" {
		t.Fatalf("sourceIPs = %#v", sourceIPs)
	}
}

func assertWebSecurityWrite(t *testing.T, r *http.Request, update bool) {
	t.Helper()
	var request struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatal(err)
	}
	if len(request.Data) != 1 {
		t.Fatalf("unexpected request data: %#v", request.Data)
	}
	if update && request.Data[0]["id"] != "web-1" {
		t.Fatalf("update ID = %#v", request.Data[0]["id"])
	}
	policies := request.Data[0]["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("policies = %#v", policies)
	}
	policy := policies[0].(map[string]any)
	if _, nested := policy["policy"]; nested {
		t.Fatalf("write retained read wrapper: %#v", policy)
	}
	from := policy["from"].(map[string]any)
	if from["groupId"] != "group-1" {
		t.Fatalf("from = %#v", from)
	}
	if update && policy["id"] != "target-a" {
		t.Fatalf("target ID = %#v", policy["id"])
	}
	urls := request.Data[0]["urls"].([]any)
	if len(urls) != 1 {
		t.Fatalf("urls = %#v", urls)
	}
	if update && urls[0].(map[string]any)["id"] != "url-a" {
		t.Fatalf("URL ID = %#v", urls[0].(map[string]any)["id"])
	}
}

func testAddressAlterationPolicy() AddressAlterationPolicy {
	enabled, enforced := true, false
	return AddressAlterationPolicy{
		ID: "policy-1", AddressAlterationSetID: "set-1",
		Policy: LegacyPolicyScope{
			Description: "rewrite", Enabled: &enabled, Enforced: &enforced,
			From: LegacyPolicyTarget{Type: "profile_group", GroupID: "group-1"}, To: LegacyPolicyTarget{Type: "everyone"},
			Conditions: &LegacyPolicyConditions{SourceIPs: []string{"10.1.0.0/16", "10.0.0.0/8"}},
		},
	}
}

func testWebSecurityPolicy() WebSecurityURLPolicy {
	enabled := true
	return WebSecurityURLPolicy{
		ID: "web-1", Description: "web policy",
		Policies: []WebSecurityTargetPolicy{{Policy: LegacyPolicyScope{
			Description: "A", Enabled: &enabled, From: LegacyPolicyTarget{Type: "profile_group", GroupID: "group-1"}, To: LegacyPolicyTarget{Type: "everyone"},
		}}},
		URLs: []WebSecurityURLAction{{Action: "allow", Type: "domain", Value: "a.example.test"}},
	}
}
