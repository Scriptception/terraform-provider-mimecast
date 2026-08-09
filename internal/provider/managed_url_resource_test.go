package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestManagedURLImportAndReadReconstructsURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
		case "/api/ttp/url/get-all-managed-urls":
			var body struct {
				Data []map[string]any `json:"data"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data) != 1 || len(body.Data[0]) != 0 {
				t.Fatalf("import read filter = %#v", body.Data)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"managed-1","scheme":"https","domain":"example.invalid","port":8443,"path":"/login","queryString":"return=%2F","matchType":"EXPLICIT","action":"BLOCK","comment":"test","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true}],"meta":{"pagination":{}}}`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	instance := &managedURLResource{client: apiClient}
	resourceSchema := managedURLSchema(t, instance)
	state := emptyManagedURLState(resourceSchema)
	importResponse := resource.ImportStateResponse{State: state}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "managed-1"}, &importResponse)
	if importResponse.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", importResponse.Diagnostics)
	}

	var imported managedURLModel
	importResponse.Diagnostics.Append(importResponse.State.Get(context.Background(), &imported)...)
	if importResponse.Diagnostics.HasError() {
		t.Fatalf("import state diagnostics: %v", importResponse.Diagnostics)
	}
	if imported.ID.ValueString() != "managed-1" || !imported.URL.IsNull() {
		t.Fatalf("imported state = %#v", imported)
	}

	readResponse := resource.ReadResponse{State: importResponse.State}
	instance.Read(context.Background(), resource.ReadRequest{State: importResponse.State}, &readResponse)
	if readResponse.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", readResponse.Diagnostics)
	}
	var got managedURLModel
	readResponse.Diagnostics.Append(readResponse.State.Get(context.Background(), &got)...)
	if readResponse.Diagnostics.HasError() {
		t.Fatalf("read state diagnostics: %v", readResponse.Diagnostics)
	}
	if got.ID.ValueString() != "managed-1" || got.URL.ValueString() != "https://example.invalid:8443/login?return=%2F" || got.Action.ValueString() != "block" || got.MatchType.ValueString() != "explicit" {
		t.Fatalf("read state = %#v", got)
	}
	if !got.DisableLogClick.ValueBool() || got.DisableRewrite.ValueBool() || !got.DisableUserAwareness.ValueBool() {
		t.Fatalf("read controls = %#v", got)
	}
}

func TestManagedURLImportReadRejectsIrrecoverableURLWithoutExposingResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"managed-invalid","scheme":"https","port":-1,"path":"/marker-path","matchType":"explicit","action":"block","comment":"marker-comment"}],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	instance := &managedURLResource{client: apiClient}
	state := emptyManagedURLState(managedURLSchema(t, instance))
	importResponse := resource.ImportStateResponse{State: state}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "managed-invalid"}, &importResponse)
	if importResponse.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", importResponse.Diagnostics)
	}

	readResponse := resource.ReadResponse{State: importResponse.State}
	instance.Read(context.Background(), resource.ReadRequest{State: importResponse.State}, &readResponse)
	if !readResponse.Diagnostics.HasError() {
		t.Fatal("expected irrecoverable managed URL read error")
	}
	diagnostic := readResponse.Diagnostics.Errors()[0]
	for _, value := range []string{"managed-invalid", "marker-path", "marker-comment"} {
		if strings.Contains(diagnostic.Detail(), value) {
			t.Fatalf("diagnostic exposed response content: %s", diagnostic.Detail())
		}
	}
}

func managedURLSchema(t *testing.T, instance resource.Resource) schema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", response.Diagnostics)
	}
	return response.Schema
}

func emptyManagedURLState(resourceSchema schema.Schema) tfsdk.State {
	return tfsdk.State{
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(context.Background()), nil),
		Schema: resourceSchema,
	}
}
