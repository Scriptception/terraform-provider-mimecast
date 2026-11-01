package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestAttributeTypesDataSourcePaginatedState(t *testing.T) {
	// Synthetic metadata, never tenant data or address attribute values.
	calls := 0
	var rejectSecondPage atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			fmt.Fprint(w, `{"access_token":"synthetic-token","expires_in":3600}`)
			return
		}
		calls++
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/directory/v1/attributeTypes" || q.Get("pageSize") != "2" || q.Has("origin") || q.Has("includeCount") {
			t.Errorf("unexpected inventory request: %s %s", r.Method, r.URL)
		}
		switch q.Get("pageToken") {
		case "":
			fmt.Fprint(w, `{"attributeTypes":[{"id":"bbbbbbbb-0000-0000-0000-000000000000","description":"LDAP link","prompt":"Department","promptGroup":"Directory","promptType":50,"promptOrder":0,"promptOptions":"","allowedInViews":false}],"meta":{"nextPage":"next+page="}}`)
		case "next+page=":
			if rejectSecondPage.Load() {
				http.Error(w, `{"errors":[{"message":"synthetic-hidden-body"}]}`, http.StatusForbidden)
				return
			}
			fmt.Fprint(w, `{"attributeTypes":[{"id":"aaaaaaaa-0000-0000-0000-000000000000","description":"Local selection","prompt":"Location","promptGroup":"Local","promptType":21,"promptOrder":1,"promptOptions":"a.First,b.Second","allowedInViews":true}],"meta":{}}`)
		default:
			t.Error("wrong page token")
			http.Error(w, "unexpected", 400)
		}
	}))
	defer s.Close()
	c, err := client.New(client.Config{BaseURL: s.URL, TokenURL: s.URL + "/oauth/token", ClientID: "id", ClientSecret: "synthetic", ReadOnly: true, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var state attributeTypesModel
	initial := readDMARCDataSourceState(t, NewAttributeTypesDataSource(), c)
	if d := initial.Get(ctx, &state); d.HasError() {
		t.Fatal(d)
	}
	if calls != 2 || len(state.Items) != 2 || state.ID.ValueString() != "attribute_types" {
		t.Fatalf("incomplete state: %#v", state)
	}
	a, b := state.Items[0], state.Items[1]
	if a.ID.ValueString() != "aaaaaaaa-0000-0000-0000-000000000000" || a.Description.ValueString() != "Local selection" || a.Prompt.ValueString() != "Location" || a.PromptGroup.ValueString() != "Local" || a.PromptType.ValueInt64() != 21 || a.PromptOrder.ValueInt64() != 1 || a.PromptOptions.ValueString() != "a.First,b.Second" || !a.AllowedInViews.ValueBool() {
		t.Fatalf("wrong typed state: %#v", a)
	}
	if b.PromptType.ValueInt64() != 50 || b.PromptOrder.IsNull() || b.PromptOrder.ValueInt64() != 0 || b.AllowedInViews.IsNull() || b.AllowedInViews.ValueBool() || b.PromptOptions.IsNull() {
		t.Fatalf("false/zero/empty fields lost: %#v", b)
	}
	rejectSecondPage.Store(true)
	instance := NewAttributeTypesDataSource().(*typedDataSource)
	instance.client = c
	response := datasource.ReadResponse{State: initial}
	instance.Read(ctx, datasource.ReadRequest{}, &response)
	if !response.Diagnostics.HasError() || response.State.Raw.String() != initial.Raw.String() {
		t.Fatal("partial inventory replaced prior state")
	}
	for _, diagnostic := range response.Diagnostics {
		if strings.Contains(diagnostic.Detail(), "synthetic-hidden-body") {
			t.Fatal("response body exposed in diagnostic")
		}
	}
	found := false
	for _, constructor := range New("test")().DataSources(ctx) {
		var m datasource.MetadataResponse
		constructor().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &m)
		if m.TypeName == "mimecast_attribute_types" {
			found = true
		}
	}
	if !found {
		t.Fatal("data source not registered")
	}
}
