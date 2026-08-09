package client

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func TestManagedURLResponseObjectDecodesComponents(t *testing.T) {
	t.Parallel()

	var item ManagedURL
	if err := json.Unmarshal([]byte(`{"id":"managed-1","scheme":"https","domain":"example.invalid","port":8443,"path":"/login","queryString":"return=%2F","matchType":"explicit","action":"block","comment":"test","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true}`), &item); err != nil {
		t.Fatal(err)
	}
	if item.ID != "managed-1" || item.Scheme != "https" || item.Domain != "example.invalid" || item.Port != 8443 || item.Path != "/login" || item.QueryString != "return=%2F" {
		t.Fatalf("decoded components = %#v", item)
	}
	if item.DisableLogClick == nil || !*item.DisableLogClick || item.DisableRewrite == nil || *item.DisableRewrite || item.DisableUserAwareness == nil || !*item.DisableUserAwareness {
		t.Fatalf("decoded controls = %#v", item)
	}

	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	for _, responseOnly := range []string{"scheme", "domain", "port", "path", "queryString"} {
		if _, found := body[responseOnly]; found {
			t.Fatalf("response-only field %q was marshalled", responseOnly)
		}
	}
}

func TestListManagedURLsCanonicalizesDocumentedResponse(t *testing.T) {
	t.Parallel()

	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"explicit-default","scheme":"https","domain":"example.invalid","port":-1,"path":"/login","queryString":"return=%2F","matchType":"EXPLICIT","action":"BLOCK"},
			{"id":"domain","scheme":"https","domain":"domain.invalid","port":443,"path":"/ignored","queryString":"ignored=true","matchType":"DOMAIN","action":"PERMIT"},
			{"id":"explicit-port","scheme":"http","domain":"port.invalid","port":8080,"path":"status","queryString":"?full=true","matchType":"explicit","action":"block"},
			{"id":"irrecoverable","scheme":"https","port":-1,"path":"/missing-domain","matchType":"explicit","action":"block"},
			{"id":"legacy","url":"https://legacy.invalid/original","scheme":"https","domain":"ignored.invalid","port":9443,"path":"/ignored","matchType":"EXPLICIT","action":"BLOCK"}
		],"meta":{"pagination":{}}}`))
	}, nil)
	defer server.Close()

	items, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]ManagedURL, len(items))
	for _, item := range items {
		got[item.ID] = item
	}
	wantURLs := map[string]string{
		"domain":           "domain.invalid",
		"explicit-default": "https://example.invalid/login?return=%2F",
		"explicit-port":    "http://port.invalid:8080/status?full=true",
		"irrecoverable":    "",
		"legacy":           "https://legacy.invalid/original",
	}
	for id, want := range wantURLs {
		if got[id].URL != want {
			t.Fatalf("%s URL = %q, want %q", id, got[id].URL, want)
		}
	}
	if got["explicit-default"].Action != "block" || got["explicit-default"].MatchType != "explicit" {
		t.Fatalf("explicit values = %#v", got["explicit-default"])
	}
	if got["domain"].Action != "permit" || got["domain"].MatchType != "domain" {
		t.Fatalf("domain values = %#v", got["domain"])
	}
}

func TestListManagedURLsUnfilteredSnapshotReturnsIndependentCopies(t *testing.T) {
	t.Parallel()

	var inventoryRequests atomic.Int32
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		inventoryRequests.Add(1)
		_, _ = w.Write([]byte(`{"data":[{"id":"managed-1","url":"example.invalid","matchType":"domain","action":"permit","disableRewrite":false}],"meta":{"pagination":{}}}`))
	}, nil)
	defer server.Close()

	first, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil || len(first) != 1 || first[0].DisableRewrite == nil {
		t.Fatalf("first=%#v error=%v", first, err)
	}
	first[0].URL = "caller-mutated.invalid"
	*first[0].DisableRewrite = true

	second, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if inventoryRequests.Load() != 1 {
		t.Fatalf("inventory requests = %d, want 1", inventoryRequests.Load())
	}
	if len(second) != 1 || second[0].URL != "example.invalid" || second[0].DisableRewrite == nil || *second[0].DisableRewrite {
		t.Fatalf("cached copy = %#v", second)
	}
}

func TestListManagedURLsUnfilteredSnapshotIsSingleFlight(t *testing.T) {
	t.Parallel()

	var inventoryRequests atomic.Int32
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if inventoryRequests.Add(1) == 1 {
			close(requestStarted)
		}
		<-releaseRequest
		_, _ = w.Write([]byte(`{"data":[{"id":"managed-1","url":"example.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{}}}`))
	}, nil)
	defer server.Close()

	const callers = 24
	start := make(chan struct{})
	results := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			items, err := c.ListManagedURLs(context.Background(), "", false)
			if err == nil && (len(items) != 1 || items[0].ID != "managed-1") {
				err = &unexpectedManagedURLResultError{}
			}
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	<-requestStarted
	close(releaseRequest)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if inventoryRequests.Load() != 1 {
		t.Fatalf("inventory requests = %d, want 1", inventoryRequests.Load())
	}
}

type unexpectedManagedURLResultError struct{}

func (*unexpectedManagedURLResultError) Error() string { return "unexpected managed URL result" }

func TestManagedURLMutationsInvalidateUnfilteredSnapshot(t *testing.T) {
	t.Parallel()

	var inventoryVersion atomic.Int32
	inventoryVersion.Store(1)
	var inventoryRequests atomic.Int32
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch r.URL.Path {
		case "/api/ttp/url/get-all-managed-urls":
			inventoryRequests.Add(1)
			switch inventoryVersion.Load() {
			case 1:
				_, _ = w.Write([]byte(`{"data":[{"id":"before","url":"before.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{}}}`))
			case 2:
				_, _ = w.Write([]byte(`{"data":[{"id":"created","url":"created.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{}}}`))
			default:
				_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{}}}`))
			}
		case "/api/ttp/url/create-managed-url":
			inventoryVersion.Store(2)
			_, _ = w.Write([]byte(`{"data":[{"id":"created"}]}`))
		case "/api/ttp/url/delete-managed-url":
			inventoryVersion.Store(3)
			_, _ = w.Write([]byte(`{"data":[{"id":"created","success":true}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}, nil)
	defer server.Close()

	first, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil || len(first) != 1 || first[0].ID != "before" {
		t.Fatalf("first=%#v error=%v", first, err)
	}
	if _, err := c.ListManagedURLs(context.Background(), "", false); err != nil {
		t.Fatal(err)
	}
	if inventoryRequests.Load() != 1 {
		t.Fatalf("cached inventory requests = %d", inventoryRequests.Load())
	}

	id, err := c.CreateManagedURL(context.Background(), ManagedURL{URL: "created.invalid", Action: "block", MatchType: "domain"})
	if err != nil || id != "created" {
		t.Fatalf("create id=%q error=%v", id, err)
	}
	afterCreate, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil || len(afterCreate) != 1 || afterCreate[0].ID != "created" || inventoryRequests.Load() != 2 {
		t.Fatalf("after create=%#v requests=%d error=%v", afterCreate, inventoryRequests.Load(), err)
	}

	if err := c.DeleteManagedURL(context.Background(), "created"); err != nil {
		t.Fatal(err)
	}
	afterDelete, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil || len(afterDelete) != 0 || inventoryRequests.Load() != 3 {
		t.Fatalf("after delete=%#v requests=%d error=%v", afterDelete, inventoryRequests.Load(), err)
	}
}

func TestManagedURLNotFoundDeleteInvalidatesUnfilteredSnapshot(t *testing.T) {
	t.Parallel()

	var inventoryRequests atomic.Int32
	var deleted atomic.Bool
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		switch r.URL.Path {
		case "/api/ttp/url/get-all-managed-urls":
			inventoryRequests.Add(1)
			if deleted.Load() {
				_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"ghost-id","url":"ghost.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{}}}`))
		case "/api/ttp/url/delete-managed-url":
			deleted.Store(true)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"fail":[{"errors":[{"code":"err_not_found","message":"not found"}]}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}, nil)
	defer server.Close()

	before, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil || len(before) != 1 || before[0].ID != "ghost-id" {
		t.Fatalf("before=%#v error=%v", before, err)
	}
	if err := c.DeleteManagedURL(context.Background(), "ghost-id"); !IsNotFound(err) {
		t.Fatalf("delete error = %v, want not found", err)
	}
	after, err := c.ListManagedURLs(context.Background(), "", false)
	if err != nil || len(after) != 0 || inventoryRequests.Load() != 2 {
		t.Fatalf("after=%#v requests=%d error=%v", after, inventoryRequests.Load(), err)
	}
}

func TestListManagedURLsSanitizesAccessTokenRecordsBeforeCaching(t *testing.T) {
	t.Parallel()

	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"unsafe-query-id","scheme":"https","domain":"unsafe-query-host.invalid","path":"/unsafe-query-path","queryString":"access_token=unsafe-query-secret","matchType":"explicit","action":"block","comment":"unsafe-query-comment"},
			{"id":"unsafe-path-id","scheme":"https","domain":"unsafe-path-host.invalid","path":"/path?access_token=unsafe-path-secret","matchType":"explicit","action":"block","comment":"unsafe-path-comment"},
			{"id":"unsafe-domain-id","domain":"unsafe-domain.invalid?access_token=unsafe-domain-secret","matchType":"domain","action":"block","comment":"unsafe-domain-comment"},
			{"id":"unsafe-ignored-path-id","domain":"safe-domain.invalid","path":"/ignored?access_token=unsafe-ignored-path-secret","matchType":"domain","action":"block","comment":"unsafe-ignored-path-comment"},
			{"id":"unsafe-invalid-explicit-id","domain":"safe-explicit.invalid","path":"/invalid?access_token=unsafe-invalid-explicit-secret","matchType":"explicit","action":"block","comment":"unsafe-invalid-explicit-comment"},
			{"id":"unsafe-scheme-id","scheme":"https?access_token=unsafe-scheme-secret","domain":"safe-scheme.invalid","matchType":"explicit","action":"block","comment":"unsafe-scheme-comment"}
		],"meta":{"pagination":{}}}`))
	}, nil)
	defer server.Close()

	for i := 0; i < 2; i++ {
		items, err := c.ListManagedURLs(context.Background(), "", false)
		if err != nil || len(items) != 6 {
			t.Fatalf("items=%#v error=%v", items, err)
		}
		for _, item := range items {
			if !ManagedURLHasAccessTokenQuery(item) {
				t.Fatalf("sanitized marker = %#v", item)
			}
			if item.URL != "" || item.Domain != "" || item.Path != "" || item.QueryString != "" || item.Comment != "" {
				t.Fatalf("unsafe record retained response values: %#v", item)
			}
		}
	}
}

func TestManagedURLCanonicalizationLeavesInvalidResponseShapesUnset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		item ManagedURL
	}{
		{name: "missing match type", item: ManagedURL{Domain: "marker.invalid"}},
		{name: "domain missing domain", item: ManagedURL{MatchType: "domain", Comment: "marker-value"}},
		{name: "explicit missing scheme", item: ManagedURL{MatchType: "explicit", Domain: "marker.invalid"}},
		{name: "explicit missing domain", item: ManagedURL{MatchType: "explicit", Scheme: "marker-scheme"}},
		{name: "explicit invalid port", item: ManagedURL{MatchType: "explicit", Scheme: "https", Domain: "marker.invalid", Port: 70000}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := test.item
			canonicalizeManagedURL(&item)
			if item.URL != "" {
				t.Fatalf("URL = %q, want empty", item.URL)
			}
		})
	}
}

func TestManagedURLAccessTokenQueryDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		item ManagedURL
		want bool
	}{
		{name: "plain composite", item: ManagedURL{URL: "https://example.invalid/path?access_token=marker"}, want: true},
		{name: "encoded composite name", item: ManagedURL{URL: "https://example.invalid/path?%61ccess%5Ftoken=marker"}, want: true},
		{name: "case insensitive composite", item: ManagedURL{URL: "https://example.invalid/path?ACCESS_TOKEN=marker"}, want: true},
		{name: "valueless parameter", item: ManagedURL{URL: "https://example.invalid/path?access_token"}, want: true},
		{name: "duplicate parameter", item: ManagedURL{URL: "https://example.invalid/path?safe=true&access_token=first&access_token=second"}, want: true},
		{name: "malformed composite URL", item: ManagedURL{URL: "://%zz?%61ccess_token=marker"}, want: true},
		{name: "decomposed query", item: ManagedURL{QueryString: "safe=true&access_token=marker"}, want: true},
		{name: "prefixed decomposed query", item: ManagedURL{QueryString: "?%61CCESS%5ftoken=marker"}, want: true},
		{name: "decomposed scheme", item: ManagedURL{Scheme: "https?access_token=marker"}, want: true},
		{name: "decomposed domain", item: ManagedURL{Domain: "example.invalid?access_token=marker"}, want: true},
		{name: "decomposed path", item: ManagedURL{Path: "/ignored?access_token=marker"}, want: true},
		{name: "value only", item: ManagedURL{URL: "https://example.invalid/path?return=access_token%3Dmarker"}},
		{name: "prefixed name", item: ManagedURL{URL: "https://example.invalid/path?my_access_token=marker"}},
		{name: "fragment only", item: ManagedURL{URL: "https://example.invalid/path#access_token=marker"}},
		{name: "query inside fragment", item: ManagedURL{URL: "https://example.invalid/path#fragment?access_token=marker"}},
		{name: "path only", item: ManagedURL{URL: "https://example.invalid/access_token=marker"}},
		{name: "safe query", item: ManagedURL{URL: "https://example.invalid/path?token=marker"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ManagedURLHasAccessTokenQuery(test.item); got != test.want {
				t.Fatalf("detection = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCreateManagedURLOmitsResponseOnlyFields(t *testing.T) {
	t.Parallel()

	disabled := false
	c, server := newFixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			tokenFixture(w)
			return
		}
		if r.URL.Path != "/api/ttp/url/create-managed-url" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var body struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 1 {
			t.Fatalf("create data = %#v", body.Data)
		}
		want := map[string]any{
			"url":            "https://example.invalid/login",
			"action":         "block",
			"matchType":      "explicit",
			"comment":        "test",
			"disableRewrite": false,
		}
		if !reflect.DeepEqual(body.Data[0], want) {
			t.Fatalf("create item = %#v, want %#v", body.Data[0], want)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"managed-1"}]}`))
	}, nil)
	defer server.Close()

	id, err := c.CreateManagedURL(context.Background(), ManagedURL{
		ID:             "response-id",
		URL:            "https://example.invalid/login",
		Action:         "block",
		MatchType:      "explicit",
		Comment:        "test",
		DisableRewrite: &disabled,
		Scheme:         "https",
		Domain:         "example.invalid",
		Port:           443,
		Path:           "/login",
		QueryString:    "ignored=true",
	})
	if err != nil || id != "managed-1" {
		t.Fatalf("id=%q error=%v", id, err)
	}
}
