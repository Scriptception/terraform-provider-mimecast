package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestAddressAlterationPolicyImportAndReadHydratesRequiredPolicy(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
		case "/api/policy/address-alteration/get-policy":
			var body struct {
				Data []map[string]string `json:"data"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data) != 1 || body.Data[0]["id"] != "policy-1" {
				t.Fatalf("import read filter = %#v", body.Data)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"rotated-policy-id","addressAlterationSetId":"rotated-set-id","policy":{"description":"Imported policy","enabled":true,"from":{"type":"everyone"},"to":{"type":"everyone"},"fromPart":"both","fromEternal":true,"toEternal":true,"conditions":{}}}]}`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	instance := &addressAlterationPolicyResource{client: apiClient}
	var schemaResponse resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", schemaResponse.Diagnostics)
	}
	state := tfsdk.State{
		Raw:    tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(context.Background()), nil),
		Schema: schemaResponse.Schema,
	}
	importResponse := resource.ImportStateResponse{State: state}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "policy-1,set-1"}, &importResponse)
	if importResponse.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", importResponse.Diagnostics)
	}

	var imported addressAlterationPolicyModel
	importResponse.Diagnostics.Append(importResponse.State.Get(context.Background(), &imported)...)
	if importResponse.Diagnostics.HasError() {
		t.Fatalf("composite import state diagnostics: %v", importResponse.Diagnostics)
	}
	if imported.ID.ValueString() != "policy-1" || imported.AddressAlterationSetID.ValueString() != "set-1" || imported.Policy != nil {
		t.Fatalf("imported state = %#v", imported)
	}

	readResponse := resource.ReadResponse{State: importResponse.State}
	instance.Read(context.Background(), resource.ReadRequest{State: importResponse.State}, &readResponse)
	if readResponse.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", readResponse.Diagnostics)
	}
	var got addressAlterationPolicyModel
	readResponse.Diagnostics.Append(readResponse.State.Get(context.Background(), &got)...)
	if readResponse.Diagnostics.HasError() {
		t.Fatalf("hydrated state diagnostics: %v", readResponse.Diagnostics)
	}
	if got.ID.ValueString() != "policy-1" || got.AddressAlterationSetID.ValueString() != "set-1" || got.Policy == nil {
		t.Fatalf("hydrated state = %#v", got)
	}
	if got.Policy.Description.ValueString() != "Imported policy" || got.Policy.From.Type.ValueString() != "everyone" || got.Policy.To.Type.ValueString() != "everyone" {
		t.Fatalf("hydrated policy = %#v", got.Policy)
	}
	if !got.Policy.Comment.IsNull() {
		t.Fatalf("omitted comment must remain null, got %#v", got.Policy.Comment)
	}
	for name, value := range map[string]types.Set{
		"source_ips":  got.Policy.SourceIPs,
		"hostnames":   got.Policy.Hostnames,
		"spf_domains": got.Policy.SPFDomains,
	} {
		if !value.IsNull() {
			t.Fatalf("omitted %s must remain null, got %#v", name, value)
		}
	}
}

func TestAddressAlterationPolicyInventoryUsesReturnedSetIdentity(t *testing.T) {
	var model addressAlterationPolicyModel
	var diagnostics diag.Diagnostics
	model.fromAPI(context.Background(), client.AddressAlterationPolicy{
		ID:                     "policy-1",
		AddressAlterationSetID: "set-1",
		Policy: client.LegacyPolicyScope{
			Description: "Inventory policy",
			From:        client.LegacyPolicyTarget{Type: "everyone"},
			To:          client.LegacyPolicyTarget{Type: "everyone"},
		},
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("inventory mapping diagnostics: %v", diagnostics)
	}
	if model.ID.ValueString() != "policy-1" || model.AddressAlterationSetID.ValueString() != "set-1" {
		t.Fatalf("inventory identities were not mapped")
	}
}

func TestAddressAlterationPolicyImportRejectsIncompleteIdentityWithoutEcho(t *testing.T) {
	marker := "never-echo-this-import-value"
	for _, importID := range []string{"", marker, marker + ",", "," + marker, marker + ",set,extra", " " + marker + ",set"} {
		instance := &addressAlterationPolicyResource{}
		var schemaResponse resource.SchemaResponse
		instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
		state := tfsdk.State{
			Raw:    tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(context.Background()), nil),
			Schema: schemaResponse.Schema,
		}
		response := resource.ImportStateResponse{State: state}
		instance.ImportState(context.Background(), resource.ImportStateRequest{ID: importID}, &response)
		if !response.Diagnostics.HasError() {
			t.Fatalf("import ID was accepted")
		}
		if strings.Contains(response.Diagnostics.Errors()[0].Detail(), marker) {
			t.Fatal("import diagnostic exposed the supplied value")
		}
	}
}
