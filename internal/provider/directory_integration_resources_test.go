package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestDirectoryIntegrationSchemasProtectWriteOnlyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		resource   resource.Resource
		secret     string
		version    string
		attributes int
	}{
		{name: "active directory", resource: NewActiveDirectoryIntegrationResource(), secret: "password_wo", version: "password_wo_version", attributes: 20},
		{name: "google workspace", resource: NewGoogleWorkspaceDirectoryIntegrationResource(), secret: "service_account_key_wo", version: "service_account_key_wo_version", attributes: 14},
		{name: "microsoft 365", resource: NewMicrosoft365DirectoryIntegrationResource(), attributes: 16},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var response resource.SchemaResponse
			test.resource.Schema(context.Background(), resource.SchemaRequest{}, &response)
			if response.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", response.Diagnostics)
			}
			if len(response.Schema.Attributes) != test.attributes {
				t.Fatalf("attributes = %d, want %d", len(response.Schema.Attributes), test.attributes)
			}
			if test.secret == "" {
				return
			}
			secret, ok := response.Schema.Attributes[test.secret].(schema.StringAttribute)
			if !ok {
				t.Fatalf("%s is not a string attribute", test.secret)
			}
			if !secret.Optional || secret.Required || !secret.WriteOnly || !secret.Sensitive || secret.Computed {
				t.Fatalf("%s schema = %#v", test.secret, secret)
			}
			version, ok := response.Schema.Attributes[test.version].(schema.Int64Attribute)
			if !ok || !version.Optional || version.Required || version.WriteOnly || version.Sensitive || version.Computed {
				t.Fatalf("%s schema = %#v", test.version, version)
			}
		})
	}
}

func TestActiveDirectoryUpdateUsesPasswordVersionTrigger(t *testing.T) {
	t.Parallel()

	prior := activeDirectoryIntegrationModel{
		Description:       types.StringValue("original"),
		Enabled:           types.BoolValue(true),
		PasswordWOVersion: types.Int64Value(1),
	}
	plan := prior
	plan.Description = types.StringValue("updated")
	plan.PasswordWO = types.StringValue("configured-but-unchanged")

	var diags diag.Diagnostics
	request := plan.updateRequest(context.Background(), prior, &diags)
	if diags.HasError() {
		t.Fatalf("diagnostics: %v", diags)
	}
	body := requestJSONMap(t, request)
	if !reflect.DeepEqual(body, map[string]any{"description": "updated"}) {
		t.Fatalf("body = %#v", body)
	}

	plan.PasswordWOVersion = types.Int64Value(2)
	plan.PasswordWO = types.StringValue("rotated-password")
	diags = nil
	request = plan.updateRequest(context.Background(), prior, &diags)
	body = requestJSONMap(t, request)
	if body["password"] != "rotated-password" || body["description"] != "updated" || len(body) != 2 {
		t.Fatalf("body = %#v", body)
	}

	plan.PasswordWO = types.StringUnknown()
	diags = nil
	request = plan.updateRequest(context.Background(), prior, &diags)
	if !diags.HasError() {
		t.Fatal("expected missing password diagnostic")
	}
	if strings.Contains(diags.Errors()[0].Detail(), "rotated-password") {
		t.Fatalf("diagnostic leaked password: %v", diags)
	}
	if _, present := requestJSONMap(t, request)["password"]; present {
		t.Fatal("unknown password was included in request")
	}
}

func TestGoogleUpdateUsesKeyVersionTrigger(t *testing.T) {
	t.Parallel()

	prior := googleDirectoryIntegrationModel{
		Description:                types.StringValue("google"),
		Enabled:                    types.BoolValue(true),
		ServiceAccountKeyWOVersion: types.Int64Value(4),
	}
	plan := prior
	plan.Enabled = types.BoolValue(false)
	plan.ServiceAccountKeyWO = types.StringValue(`{"private_key":"unchanged"}`)

	var diags diag.Diagnostics
	request := plan.updateRequest(context.Background(), prior, &diags)
	body := requestJSONMap(t, request)
	if !reflect.DeepEqual(body, map[string]any{"enabled": false}) {
		t.Fatalf("body = %#v", body)
	}

	plan.ServiceAccountKeyWOVersion = types.Int64Value(5)
	plan.ServiceAccountKeyWO = types.StringValue(`{"private_key":"rotated"}`)
	diags = nil
	request = plan.updateRequest(context.Background(), prior, &diags)
	body = requestJSONMap(t, request)
	if body["key"] != `{"private_key":"rotated"}` || body["enabled"] != false || len(body) != 2 {
		t.Fatalf("body = %#v", body)
	}
}

func TestDirectoryCreateOmitsUnknownOptionalFields(t *testing.T) {
	t.Parallel()

	model := activeDirectoryIntegrationModel{
		Description:                 types.StringValue("primary"),
		Info:                        types.StringUnknown(),
		Domains:                     types.ListUnknown(types.StringType),
		Hostname:                    types.StringValue("ad.example.com"),
		AlternateHostname:           types.StringValue("ad2.example.com"),
		Port:                        types.Int64Unknown(),
		UserDN:                      types.StringValue("CN=sync"),
		PasswordWO:                  types.StringValue("password"),
		PasswordWOVersion:           types.Int64Value(1),
		RootDN:                      types.StringValue("DC=example,DC=com"),
		EncryptionMode:              types.StringUnknown(),
		AcknowledgeDisabledAccounts: types.BoolUnknown(),
		Enabled:                     types.BoolUnknown(),
		MaxUnlink:                   types.StringUnknown(),
		SyncContacts:                types.BoolUnknown(),
		DeleteUsers:                 types.BoolUnknown(),
	}
	var diags diag.Diagnostics
	body := requestJSONMap(t, model.createRequest(context.Background(), &diags))
	if diags.HasError() {
		t.Fatalf("diagnostics: %v", diags)
	}
	expected := map[string]any{
		"description": "primary", "hostname": "ad.example.com", "alternateHostname": "ad2.example.com",
		"userDn": "CN=sync", "password": "password", "rootDn": "DC=example,DC=com",
	}
	if !reflect.DeepEqual(body, expected) {
		t.Fatalf("body = %#v, want %#v", body, expected)
	}
}

func TestMicrosoft365UpdateOnlyIncludesChangedDocumentedFields(t *testing.T) {
	t.Parallel()

	domains := types.ListValueMust(types.StringType, []attr.Value{types.StringValue("example.com")})
	prior := microsoft365DirectoryIntegrationModel{
		Description:    types.StringValue("m365"),
		Domains:        domains,
		TenantDomain:   types.StringValue("tenant.onmicrosoft.com"),
		SyncGuestUsers: types.BoolValue(true),
		ClientID:       types.StringValue("read-only-client-id"),
	}
	plan := prior
	plan.SyncGuestUsers = types.BoolValue(false)
	plan.ClientID = types.StringValue("different-read-only-value")
	var diags diag.Diagnostics
	body := requestJSONMap(t, plan.updateRequest(context.Background(), prior, &diags))
	if diags.HasError() {
		t.Fatalf("diagnostics: %v", diags)
	}
	if !reflect.DeepEqual(body, map[string]any{"syncGuestUsers": false}) {
		t.Fatalf("body = %#v", body)
	}
}

func TestDirectoryIntegrationImportSetsID(t *testing.T) {
	t.Parallel()

	resources := []struct {
		resource resource.ResourceWithImportState
		secret   string
	}{
		{resource: NewActiveDirectoryIntegrationResource().(resource.ResourceWithImportState), secret: "password_wo"},
		{resource: NewGoogleWorkspaceDirectoryIntegrationResource().(resource.ResourceWithImportState), secret: "service_account_key_wo"},
		{resource: NewMicrosoft365DirectoryIntegrationResource().(resource.ResourceWithImportState)},
	}
	for _, test := range resources {
		var schemaResponse resource.SchemaResponse
		test.resource.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
		state := emptyDirectoryState(schemaResponse.Schema)
		response := resource.ImportStateResponse{State: state}
		test.resource.ImportState(context.Background(), resource.ImportStateRequest{ID: "integration-id"}, &response)
		if response.Diagnostics.HasError() {
			t.Fatalf("import diagnostics: %v", response.Diagnostics)
		}
		var id types.String
		response.Diagnostics.Append(response.State.GetAttribute(context.Background(), path.Root("id"), &id)...)
		if response.Diagnostics.HasError() || id.ValueString() != "integration-id" {
			t.Fatalf("imported id = %q diagnostics=%v", id.ValueString(), response.Diagnostics)
		}
		if test.secret != "" {
			var secret types.String
			response.Diagnostics.Append(response.State.GetAttribute(context.Background(), path.Root(test.secret), &secret)...)
			if response.Diagnostics.HasError() || !secret.IsNull() {
				t.Fatalf("imported %s must be null, value=%v diagnostics=%v", test.secret, secret, response.Diagnostics)
			}
		}
	}
}

func TestDirectoryIntegrationReadRemovesExternallyDeletedResource(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"not_found","message":"not found"}]}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		resource resource.Resource
		read     func(context.Context, resource.ReadRequest, *resource.ReadResponse)
	}{
		{
			name:     "active directory",
			resource: NewActiveDirectoryIntegrationResource(),
			read: func(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
				r := &activeDirectoryIntegrationResource{client: apiClient}
				r.Read(ctx, request, response)
			},
		},
		{
			name:     "google workspace",
			resource: NewGoogleWorkspaceDirectoryIntegrationResource(),
			read: func(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
				r := &googleDirectoryIntegrationResource{client: apiClient}
				r.Read(ctx, request, response)
			},
		},
		{
			name:     "microsoft 365",
			resource: NewMicrosoft365DirectoryIntegrationResource(),
			read: func(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
				r := &microsoft365DirectoryIntegrationResource{client: apiClient}
				r.Read(ctx, request, response)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var schemaResponse resource.SchemaResponse
			test.resource.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
			state := emptyDirectoryState(schemaResponse.Schema)
			if diags := state.SetAttribute(context.Background(), path.Root("id"), "missing"); diags.HasError() {
				t.Fatalf("state diagnostics: %v", diags)
			}
			response := resource.ReadResponse{State: state}
			test.read(context.Background(), resource.ReadRequest{State: state}, &response)
			if response.Diagnostics.HasError() {
				t.Fatalf("read diagnostics: %v", response.Diagnostics)
			}
			if !response.State.Raw.IsNull() {
				t.Fatalf("state was not removed: %s", response.State.Raw.String())
			}
		})
	}
}

func requestJSONMap(t *testing.T, request any) map[string]any {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func emptyDirectoryState(resourceSchema schema.Schema) tfsdk.State {
	return tfsdk.State{
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(context.Background()), nil),
		Schema: resourceSchema,
	}
}
