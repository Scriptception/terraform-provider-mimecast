package provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestManagedURLsDataSourceExcludesWholeAccessTokenRecords(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
		case "/api/ttp/url/get-all-managed-urls":
			_, _ = w.Write([]byte(`{"data":[
				{"id":"safe-a","url":"https://safe-a.invalid/path?return=true","matchType":"explicit","action":"block","comment":"safe-a"},
				{"id":"excluded-composite-marker","url":"https://excluded.invalid/path?%61ccess%5Ftoken=excluded-secret-marker","matchType":"explicit","action":"block","comment":"excluded-comment-marker"},
				{"id":"excluded-decomposed-marker","scheme":"https","port":-1,"path":"/excluded-path-marker","queryString":"ACCESS_TOKEN=excluded-decomposed-secret-marker","matchType":"explicit","action":"block","comment":"excluded-decomposed-comment-marker"},
				{"id":"safe-z","url":"https://safe-z.invalid/path?return=access_token%3Dsafe-value-marker","matchType":"explicit","action":"permit","comment":"safe-z"}
			],"meta":{"pagination":{}}}`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	state := readDMARCDataSourceState(t, NewManagedURLsDataSource(), apiClient)
	var got managedURLsModel
	if diagnostics := state.Get(t.Context(), &got); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if got.ExcludedAccessTokenCount.ValueInt64() != 2 {
		t.Fatalf("excluded count = %d, want 2", got.ExcludedAccessTokenCount.ValueInt64())
	}
	if len(got.Items) != 2 || got.Items[0].ID.ValueString() != "safe-a" || got.Items[1].ID.ValueString() != "safe-z" {
		t.Fatalf("safe managed URL ordering = %#v", got.Items)
	}
	if got.Items[1].URL.ValueString() != "https://safe-z.invalid/path?return=access_token%3Dsafe-value-marker" {
		t.Fatal("a parameter value containing access_token text was incorrectly excluded")
	}
	for _, marker := range []string{
		"excluded-composite-marker",
		"excluded-secret-marker",
		"excluded-comment-marker",
		"excluded-decomposed-marker",
		"excluded-path-marker",
		"excluded-decomposed-secret-marker",
		"excluded-decomposed-comment-marker",
	} {
		if strings.Contains(state.Raw.String(), marker) {
			t.Fatal("excluded managed URL marker entered state")
		}
	}
}
