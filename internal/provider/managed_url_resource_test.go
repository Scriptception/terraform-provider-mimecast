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
		var body struct {
			Data []json.RawMessage `json:"data"`
			Meta struct {
				Pagination struct {
					PageToken string `json:"pageToken"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 0 {
			t.Fatal("unfiltered privacy import included a filter")
		}
		if body.Meta.Pagination.PageToken == "" {
			_, _ = w.Write([]byte(`{"data":[{"id":"other","url":"other.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{"next":"privacy-page-2"}}}`))
			return
		}
		if body.Meta.Pagination.PageToken != "privacy-page-2" {
			t.Fatalf("unexpected page token %q", body.Meta.Pagination.PageToken)
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

	inventoryPages := 0
	filteredReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
		case "/api/ttp/url/get-all-managed-urls":
			var body struct {
				Data []struct {
					DomainOrURL string `json:"domainOrUrl"`
					ExactMatch  bool   `json:"exactMatch"`
				} `json:"data"`
				Meta struct {
					Pagination struct {
						PageToken string `json:"pageToken"`
					} `json:"pagination"`
				} `json:"meta"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data) != 0 {
				filteredReads++
				if len(body.Data) != 1 || body.Data[0].DomainOrURL != "https://example.invalid:8443/login?return=%2F" || !body.Data[0].ExactMatch {
					t.Fatalf("filtered request = %#v", body.Data)
				}
				_, _ = w.Write([]byte(`{"data":[{"id":"rotated-response-id","scheme":"https","domain":"example.invalid","port":8443,"path":"/login","queryString":"return=%2F","matchType":"EXPLICIT","action":"BLOCK","comment":"test","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true}],"meta":{"pagination":{}}}`))
				return
			}
			inventoryPages++
			switch body.Meta.Pagination.PageToken {
			case "":
				_, _ = w.Write([]byte(`{"data":[{"id":"unrelated","url":"unrelated.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{"next":"import-page-2"}}}`))
			case "import-page-2":
				_, _ = w.Write([]byte(`{"data":[{"id":"managed-1","scheme":"https","domain":"example.invalid","port":8443,"path":"/login","queryString":"return=%2F","matchType":"EXPLICIT","action":"BLOCK","comment":"test","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true}],"meta":{"pagination":{}}}`))
			default:
				t.Fatalf("unexpected page token %q", body.Meta.Pagination.PageToken)
			}
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
	if imported.ID.ValueString() != "managed-1" || imported.URL.ValueString() != "https://example.invalid:8443/login?return=%2F" || imported.Action.ValueString() != "block" || imported.MatchType.ValueString() != "explicit" {
		t.Fatalf("imported state = %#v", imported)
	}
	if !imported.DisableLogClick.ValueBool() || imported.DisableRewrite.ValueBool() || !imported.DisableUserAwareness.ValueBool() {
		t.Fatalf("imported controls = %#v", imported)
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
	if inventoryPages != 2 || filteredReads != 1 {
		t.Fatalf("inventory pages=%d filtered reads=%d", inventoryPages, filteredReads)
	}
}

func TestManagedURLImportRejectsIrrecoverableURLWithoutExposingResponse(t *testing.T) {
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
	if !importResponse.Diagnostics.HasError() {
		t.Fatal("expected irrecoverable managed URL import error")
	}
	diagnostic := importResponse.Diagnostics.Errors()[0]
	if diagnostic.Detail() != managedURLUnreconstructibleDetail {
		t.Fatalf("diagnostic detail = %q", diagnostic.Detail())
	}
	for _, value := range []string{"managed-invalid", "marker-path", "marker-comment"} {
		if strings.Contains(diagnostic.Detail(), value) {
			t.Fatalf("diagnostic exposed response content: %s", diagnostic.Detail())
		}
	}
	if !importResponse.State.Raw.IsNull() {
		t.Fatal("irreconstructible imported record must not be written to state")
	}
}

func TestManagedURLImportThenFilteredMissUsesGlobalSnapshot(t *testing.T) {
	t.Parallel()

	inventoryReads := 0
	filteredReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) == 0 {
			inventoryReads++
			_, _ = w.Write([]byte(`{"data":[{"id":"stable-domain-id","url":"tracked.example.invalid","matchType":"domain","action":"block","comment":"tracked"}],"meta":{"pagination":{}}}`))
			return
		}
		filteredReads++
		_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	importResponse := resource.ImportStateResponse{State: emptyManagedURLState(resourceSchema)}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "stable-domain-id"}, &importResponse)
	if importResponse.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", importResponse.Diagnostics)
	}

	readResponse := resource.ReadResponse{State: importResponse.State}
	instance.Read(context.Background(), resource.ReadRequest{State: importResponse.State}, &readResponse)
	if readResponse.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", readResponse.Diagnostics)
	}
	var got managedURLModel
	readResponse.Diagnostics.Append(readResponse.State.Get(context.Background(), &got)...)
	if got.ID.ValueString() != "stable-domain-id" || got.URL.ValueString() != "tracked.example.invalid" || got.Comment.ValueString() != "tracked" {
		t.Fatalf("state = %#v", got)
	}
	if inventoryReads != 1 || filteredReads != 1 {
		t.Fatalf("inventory reads=%d filtered reads=%d", inventoryReads, filteredReads)
	}
}

func TestManagedURLReadAcceptsDuplicateSemanticMatchesWithoutChangingID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) == 0 {
			t.Fatal("semantic duplicate match unexpectedly used global inventory")
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"rotated-a","url":"https://duplicate.example.invalid/path","matchType":"explicit","action":"block","comment":"same","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true},
			{"id":"rotated-b","url":"https://duplicate.example.invalid/path","matchType":"explicit","action":"block","comment":"same","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true}
		],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	model := completeManagedURLTestModel("stable-id", "https://duplicate.example.invalid/path")
	state := managedURLState(t, resourceSchema, model)
	response := resource.ReadResponse{State: state}
	instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", response.Diagnostics)
	}
	var got managedURLModel
	response.Diagnostics.Append(response.State.Get(context.Background(), &got)...)
	if got.ID.ValueString() != "stable-id" || !got.semanticallyMatches(model.toAPI()) {
		t.Fatalf("state = %#v", got)
	}
}

func TestManagedURLReadPrefersExactIDOverEarlierSemanticDuplicate(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"rotated-semantic","url":"https://old.example.invalid/path","matchType":"explicit","action":"block","comment":"same","disableLogClick":true,"disableRewrite":false,"disableUserAwareness":true},
			{"id":"stable-id","url":"https://changed.example.invalid/path","matchType":"explicit","action":"permit","comment":"changed","disableLogClick":false,"disableRewrite":true,"disableUserAwareness":false}
		],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	state := managedURLState(t, resourceSchema, completeManagedURLTestModel("stable-id", "https://old.example.invalid/path"))
	response := resource.ReadResponse{State: state}
	instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", response.Diagnostics)
	}
	var got managedURLModel
	response.Diagnostics.Append(response.State.Get(context.Background(), &got)...)
	if got.ID.ValueString() != "stable-id" || got.URL.ValueString() != "https://changed.example.invalid/path" || got.Action.ValueString() != "permit" || got.Comment.ValueString() != "changed" {
		t.Fatalf("state = %#v", got)
	}
	if got.DisableLogClick.ValueBool() || !got.DisableRewrite.ValueBool() || got.DisableUserAwareness.ValueBool() {
		t.Fatalf("controls = %#v", got)
	}
}

func TestManagedURLReadRefreshesChangedRecordFromGlobalFallback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 0 {
			_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"stable-id","url":"changed.example.invalid","matchType":"domain","action":"permit","comment":"changed remotely","disableLogClick":false,"disableRewrite":true,"disableUserAwareness":false}],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	state := managedURLState(t, resourceSchema, completeManagedURLTestModel("stable-id", "https://old.example.invalid/path"))
	response := resource.ReadResponse{State: state}
	instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", response.Diagnostics)
	}
	var got managedURLModel
	response.Diagnostics.Append(response.State.Get(context.Background(), &got)...)
	if got.ID.ValueString() != "stable-id" || got.URL.ValueString() != "changed.example.invalid" || got.MatchType.ValueString() != "domain" || got.Action.ValueString() != "permit" || got.Comment.ValueString() != "changed remotely" {
		t.Fatalf("state = %#v", got)
	}
	if got.DisableLogClick.ValueBool() || !got.DisableRewrite.ValueBool() || got.DisableUserAwareness.ValueBool() {
		t.Fatalf("controls = %#v", got)
	}
}

func TestManagedURLReadRemovesOnlyAfterPaginatedGlobalAbsence(t *testing.T) {
	t.Parallel()

	globalPages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
			Meta struct {
				Pagination struct {
					PageToken string `json:"pageToken"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 0 {
			_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{}}}`))
			return
		}
		globalPages++
		if body.Meta.Pagination.PageToken == "" {
			_, _ = w.Write([]byte(`{"data":[{"id":"other-a","url":"a.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{"next":"delete-page-2"}}}`))
			return
		}
		if body.Meta.Pagination.PageToken != "delete-page-2" {
			t.Fatalf("unexpected page token %q", body.Meta.Pagination.PageToken)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"other-b","url":"b.invalid","matchType":"domain","action":"block"}],"meta":{"pagination":{}}}`))
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	state := managedURLState(t, resourceSchema, completeManagedURLTestModel("deleted-id", "https://old.example.invalid/path"))
	response := resource.ReadResponse{State: state}
	instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", response.Diagnostics)
	}
	if !response.State.Raw.IsNull() {
		t.Fatal("globally absent managed URL was not removed")
	}
	if globalPages != 2 {
		t.Fatalf("global pages = %d", globalPages)
	}
}

func TestManagedURLReadGlobalFailureRetainsState(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		var body struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != 0 {
			_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{}}}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`temporarily unavailable`))
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	model := completeManagedURLTestModel("stable-id", "https://old.example.invalid/path")
	state := managedURLState(t, resourceSchema, model)
	response := resource.ReadResponse{State: state}
	instance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("expected global inventory failure")
	}
	if response.State.Raw.IsNull() {
		t.Fatal("global inventory failure removed state")
	}
}

func TestManagedURLCreateSeedsFromUnfilteredExactID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
		case "/api/ttp/url/create-managed-url":
			_, _ = w.Write([]byte(`{"data":[{"id":"created-stable-id"}]}`))
		case "/api/ttp/url/get-all-managed-urls":
			var body struct {
				Data []json.RawMessage `json:"data"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Data) != 0 {
				t.Fatal("created managed URL was read with a filter")
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"created-stable-id","url":"created.example.invalid","matchType":"domain","action":"block","comment":"created"}],"meta":{"pagination":{}}}`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	instance := &managedURLResource{client: managedURLTestClient(t, server)}
	resourceSchema := managedURLSchema(t, instance)
	plan := managedURLTestModel("created.example.invalid")
	plan.MatchType = types.StringValue("domain")
	response := resource.CreateResponse{State: emptyManagedURLState(resourceSchema)}
	instance.Create(context.Background(), resource.CreateRequest{Plan: managedURLPlan(t, resourceSchema, plan)}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("create diagnostics: %v", response.Diagnostics)
	}
	var got managedURLModel
	response.Diagnostics.Append(response.State.Get(context.Background(), &got)...)
	if got.ID.ValueString() != "created-stable-id" || got.URL.ValueString() != "created.example.invalid" || got.Comment.ValueString() != "created" {
		t.Fatalf("created state = %#v", got)
	}
}

func TestManagedURLSemanticMatchCoversAllFields(t *testing.T) {
	t.Parallel()

	trueValue := true
	falseValue := false
	base := completeManagedURLTestModel("stable-id", "https://example.invalid/path")
	remote := base.toAPI()
	remote.ID = "rotated-id"
	if !base.semanticallyMatches(remote) {
		t.Fatal("identical managed URL did not semantically match")
	}

	tests := []struct {
		name   string
		mutate func(*client.ManagedURL)
	}{
		{name: "url", mutate: func(item *client.ManagedURL) { item.URL = "https://other.invalid/path" }},
		{name: "action", mutate: func(item *client.ManagedURL) { item.Action = "permit" }},
		{name: "match type", mutate: func(item *client.ManagedURL) { item.MatchType = "domain" }},
		{name: "comment", mutate: func(item *client.ManagedURL) { item.Comment = "other" }},
		{name: "disable log click", mutate: func(item *client.ManagedURL) { item.DisableLogClick = &falseValue }},
		{name: "disable rewrite", mutate: func(item *client.ManagedURL) { item.DisableRewrite = &trueValue }},
		{name: "disable user awareness", mutate: func(item *client.ManagedURL) { item.DisableUserAwareness = &falseValue }},
		{name: "nil differs from false", mutate: func(item *client.ManagedURL) { item.DisableRewrite = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := remote
			test.mutate(&candidate)
			if base.semanticallyMatches(candidate) {
				t.Fatal("different managed URL semantically matched")
			}
		})
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

func completeManagedURLTestModel(id, url string) managedURLModel {
	return managedURLModel{
		ID:                   types.StringValue(id),
		URL:                  types.StringValue(url),
		Action:               types.StringValue("block"),
		MatchType:            types.StringValue("explicit"),
		Comment:              types.StringValue("same"),
		DisableLogClick:      types.BoolValue(true),
		DisableRewrite:       types.BoolValue(false),
		DisableUserAwareness: types.BoolValue(true),
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
