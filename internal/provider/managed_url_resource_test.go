package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestManagedURLSchemaRejectsAccessTokenQueryWithoutExposingValue(t *testing.T) {
	t.Parallel()

	resourceSchema := managedURLSchema(t, NewManagedURLResource())
	attribute, ok := resourceSchema.Attributes["url"].(schema.StringAttribute)
	if !ok || len(attribute.Validators) == 0 {
		t.Fatalf("managed URL must have a URL validator: %#v", attribute)
	}
	unsafeValue := "https://diagnostic-host.invalid/path?%61CCESS%5ftoken=diagnostic-secret-marker"
	request := validator.StringRequest{ConfigValue: types.StringValue(unsafeValue), Path: path.Root("url")}
	var response validator.StringResponse
	for _, validate := range attribute.Validators {
		validate.ValidateString(context.Background(), request, &response)
	}
	if !response.Diagnostics.HasError() {
		t.Fatal("access_token query name must be rejected")
	}
	assertDiagnosticsExclude(t, response.Diagnostics, unsafeValue, "diagnostic-host.invalid", "diagnostic-secret-marker")

	for _, safeValue := range []string{
		"https://example.invalid/path?return=access_token%3Dmarker",
		"https://example.invalid/path?my_access_token=marker",
	} {
		response = validator.StringResponse{}
		request.ConfigValue = types.StringValue(safeValue)
		for _, validate := range attribute.Validators {
			validate.ValidateString(context.Background(), request, &response)
		}
		if response.Diagnostics.HasError() {
			t.Fatalf("safe managed URL diagnostics: %v", response.Diagnostics)
		}
	}
}

func TestManagedURLResourceDirectGuardsRejectUnsafePlanAndStateBeforeAPI(t *testing.T) {
	t.Parallel()

	instance := &managedURLResource{}
	resourceSchema := managedURLSchema(t, instance)
	unsafeValue := "https://direct-guard.invalid/path?%61ccess_token=direct-secret-marker"
	model := managedURLTestModel(unsafeValue)

	t.Run("create", func(t *testing.T) {
		response := resource.CreateResponse{State: emptyManagedURLState(resourceSchema)}
		instance.Create(context.Background(), resource.CreateRequest{Plan: managedURLPlan(t, resourceSchema, model)}, &response)
		assertManagedURLAccessTokenDiagnostic(t, response.Diagnostics, unsafeValue, "direct-secret-marker")
	})

	t.Run("update", func(t *testing.T) {
		response := resource.UpdateResponse{State: emptyManagedURLState(resourceSchema)}
		instance.Update(context.Background(), resource.UpdateRequest{Plan: managedURLPlan(t, resourceSchema, model)}, &response)
		assertManagedURLAccessTokenDiagnostic(t, response.Diagnostics, unsafeValue, "direct-secret-marker")
	})

	t.Run("read", func(t *testing.T) {
		state := managedURLState(t, resourceSchema, model)
		response := resource.ReadResponse{State: state}
		instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
		assertManagedURLAccessTokenDiagnostic(t, response.Diagnostics, unsafeValue, "direct-secret-marker")
	})
}

func TestManagedURLCreateRejectsUnsafeReadbackWithoutWritingState(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
		case "/api/ttp/url/create-managed-url":
			_, _ = w.Write([]byte(`{"data":[{"id":"created-id-marker"}]}`))
		case "/api/ttp/url/get-all-managed-urls":
			_, _ = w.Write([]byte(`{"data":[{"id":"created-id-marker","url":"https://remote-marker.invalid/path?access_token=remote-secret-marker","matchType":"explicit","action":"block","comment":"remote-comment-marker"}],"meta":{"pagination":{}}}`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	apiClient := managedURLTestClient(t, server)
	instance := &managedURLResource{client: apiClient}
	resourceSchema := managedURLSchema(t, instance)
	response := resource.CreateResponse{State: emptyManagedURLState(resourceSchema)}
	instance.Create(context.Background(), resource.CreateRequest{Plan: managedURLPlan(t, resourceSchema, managedURLTestModel("https://safe.invalid/path"))}, &response)
	assertManagedURLAccessTokenDiagnostic(t, response.Diagnostics, "remote-marker.invalid", "remote-secret-marker", "remote-comment-marker", "created-id-marker")
	if !response.State.Raw.IsNull() {
		t.Fatal("unsafe create readback must not be written to state")
	}
}

func TestManagedURLReadRejectsUnsafeRemoteRecordWithoutWritingState(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"read-id-marker","url":"https://remote-read-marker.invalid/path?%61ccess_token=remote-read-secret-marker","matchType":"explicit","action":"block","comment":"remote-read-comment-marker"}],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	apiClient := managedURLTestClient(t, server)
	instance := &managedURLResource{client: apiClient}
	resourceSchema := managedURLSchema(t, instance)
	model := managedURLTestModel("https://safe.invalid/path")
	model.ID = types.StringValue("read-id-marker")
	state := managedURLState(t, resourceSchema, model)
	response := resource.ReadResponse{State: state}
	instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	assertManagedURLAccessTokenDiagnostic(t, response.Diagnostics, "remote-read-marker.invalid", "remote-read-secret-marker", "remote-read-comment-marker", "read-id-marker")

	var got managedURLModel
	if diagnostics := response.State.Get(context.Background(), &got); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if got.URL.ValueString() != "https://safe.invalid/path" {
		t.Fatal("unsafe remote record changed managed URL state")
	}
}

func TestManagedURLImportRejectsUnsafeDecomposedRecordWithoutWritingState(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"import-id-marker","scheme":"https","port":-1,"path":"/import-path-marker","queryString":"ACCESS_TOKEN=import-secret-marker","matchType":"explicit","action":"block","comment":"import-comment-marker"}],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	apiClient := managedURLTestClient(t, server)
	instance := &managedURLResource{client: apiClient}
	state := emptyManagedURLState(managedURLSchema(t, instance))
	response := resource.ImportStateResponse{State: state}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "import-id-marker"}, &response)
	assertManagedURLAccessTokenDiagnostic(t, response.Diagnostics, "import-id-marker", "import-path-marker", "import-secret-marker", "import-comment-marker")
	if !response.State.Raw.IsNull() {
		t.Fatal("unsafe imported record must not be written to state")
	}
}

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

func managedURLTestModel(url string) managedURLModel {
	return managedURLModel{
		ID:                   types.StringNull(),
		URL:                  types.StringValue(url),
		Action:               types.StringValue("block"),
		MatchType:            types.StringValue("explicit"),
		Comment:              types.StringNull(),
		DisableLogClick:      types.BoolNull(),
		DisableRewrite:       types.BoolNull(),
		DisableUserAwareness: types.BoolNull(),
	}
}

func managedURLState(t *testing.T, resourceSchema schema.Schema, model managedURLModel) tfsdk.State {
	t.Helper()
	state := emptyManagedURLState(resourceSchema)
	if diagnostics := state.Set(context.Background(), &model); diagnostics.HasError() {
		t.Fatalf("managed URL state diagnostics: %v", diagnostics)
	}
	return state
}

func managedURLPlan(t *testing.T, resourceSchema schema.Schema, model managedURLModel) tfsdk.Plan {
	t.Helper()
	state := managedURLState(t, resourceSchema, model)
	return tfsdk.Plan{Raw: state.Raw, Schema: resourceSchema}
}

func managedURLTestClient(t *testing.T, server *httptest.Server) *client.Client {
	t.Helper()
	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	return apiClient
}

func assertManagedURLAccessTokenDiagnostic(t *testing.T, diagnostics diag.Diagnostics, forbidden ...string) {
	t.Helper()
	if !diagnostics.HasError() {
		t.Fatal("expected access_token rejection diagnostic")
	}
	errors := diagnostics.Errors()
	if len(errors) == 0 || errors[0].Summary() != managedURLAccessTokenSummary || errors[0].Detail() != managedURLAccessTokenDetail {
		t.Fatal("unexpected managed URL access_token diagnostic")
	}
	assertDiagnosticsExclude(t, diagnostics, forbidden...)
}
