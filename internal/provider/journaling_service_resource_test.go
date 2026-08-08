package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestJournalingServiceSchemaProtectsOptionalPasswords(t *testing.T) {
	t.Parallel()

	var response resource.SchemaResponse
	NewJournalingServiceResource().Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", response.Diagnostics)
	}
	for _, pair := range []struct {
		password string
		version  string
	}{
		{password: "smtp_password_wo", version: "smtp_password_wo_version"},
		{password: "pop3_password_wo", version: "pop3_password_wo_version"},
	} {
		password := response.Schema.Attributes[pair.password].(schema.StringAttribute)
		if !password.Optional || password.Required || !password.WriteOnly || !password.Sensitive || password.Computed {
			t.Fatalf("%s schema = %#v", pair.password, password)
		}
		version := response.Schema.Attributes[pair.version].(schema.Int64Attribute)
		if !version.Optional || version.Required || version.WriteOnly || version.Sensitive || version.Computed {
			t.Fatalf("%s schema = %#v", pair.version, version)
		}
	}
}

func TestJournalingServiceCreateValidatesSelectedConnection(t *testing.T) {
	t.Parallel()

	smtp := nullJournalingServiceModel()
	smtp.Description = types.StringValue("smtp journal")
	smtp.TransferProtocol = types.StringValue("smtp")
	smtp.SMTPEmailAddress = types.StringValue("journal@example.com")
	smtp.SMTPUsesAuthentication = types.BoolValue(true)
	var smtpDiags diag.Diagnostics
	request := smtp.createRequest(context.Background(), &smtpDiags)
	if !smtpDiags.HasError() {
		t.Fatal("authenticated SMTP create must require smtp_password_wo")
	}
	if request.POP3JournalingConnection != nil {
		t.Fatal("SMTP create included POP3 connection")
	}

	pop3 := nullJournalingServiceModel()
	pop3.Description = types.StringValue("pop3 journal")
	pop3.TransferProtocol = types.StringValue("pop3")
	pop3.POP3EmailAddress = types.StringValue("journal@example.com")
	pop3.POP3Mailbox = types.StringValue("journal")
	pop3.POP3Host = types.StringValue("pop.example.com")
	var pop3Diags diag.Diagnostics
	request = pop3.createRequest(context.Background(), &pop3Diags)
	if !pop3Diags.HasError() {
		t.Fatal("POP3 create must require pop3_password_wo")
	}
	if request.SMTPJournalingConnection != nil {
		t.Fatal("POP3 create included SMTP connection")
	}

	for _, diagnostics := range []diag.Diagnostics{smtpDiags, pop3Diags} {
		if strings.Contains(diagnostics.Errors()[0].Detail(), "password-value") {
			t.Fatalf("diagnostic leaked password: %v", diagnostics)
		}
	}
}

func TestJournalingServicePasswordUpdatesNeedVersionTrigger(t *testing.T) {
	t.Parallel()

	prior := nullJournalingServiceModel()
	prior.ID = types.StringValue("journal-id")
	prior.Description = types.StringValue("journal")
	prior.TransferProtocol = types.StringValue("smtp")
	prior.SMTPEmailAddress = types.StringValue("journal@example.com")
	prior.SMTPUsesAuthentication = types.BoolValue(true)
	prior.SMTPPasswordWOVersion = types.Int64Value(1)

	plan := prior
	plan.Description = types.StringValue("updated")
	plan.SMTPPasswordWO = types.StringValue("configured-but-unchanged")
	var diagnostics diag.Diagnostics
	request := plan.updateRequest(context.Background(), prior, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", diagnostics)
	}
	body := requestJSONMap(t, request)
	if !reflect.DeepEqual(body, map[string]any{"description": "updated"}) {
		t.Fatalf("body = %#v", body)
	}

	plan.SMTPPasswordWOVersion = types.Int64Value(2)
	plan.SMTPPasswordWO = types.StringValue("rotated-password")
	diagnostics = nil
	request = plan.updateRequest(context.Background(), prior, &diagnostics)
	body = requestJSONMap(t, request)
	expected := map[string]any{
		"description":              "updated",
		"smtpJournalingConnection": map[string]any{"password": "rotated-password"},
	}
	if !reflect.DeepEqual(body, expected) {
		t.Fatalf("body = %#v, want %#v", body, expected)
	}
}

func TestImportedJournalingServiceNeedsNoPasswordsOrUpdate(t *testing.T) {
	t.Parallel()

	resourceInstance := NewJournalingServiceResource().(resource.ResourceWithImportState)
	var schemaResponse resource.SchemaResponse
	resourceInstance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	state := emptyDirectoryState(schemaResponse.Schema)
	response := resource.ImportStateResponse{State: state}
	resourceInstance.ImportState(context.Background(), resource.ImportStateRequest{ID: "journal-id"}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", response.Diagnostics)
	}
	for _, name := range []string{"smtp_password_wo", "smtp_password_wo_version", "pop3_password_wo", "pop3_password_wo_version"} {
		switch {
		case strings.HasSuffix(name, "_version"):
			var value types.Int64
			response.Diagnostics.Append(response.State.GetAttribute(context.Background(), path.Root(name), &value)...)
			if !value.IsNull() {
				t.Fatalf("imported %s = %v, want null", name, value)
			}
		default:
			var value types.String
			response.Diagnostics.Append(response.State.GetAttribute(context.Background(), path.Root(name), &value)...)
			if !value.IsNull() {
				t.Fatalf("imported %s = %v, want null", name, value)
			}
		}
	}
	if response.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", response.Diagnostics)
	}

	imported := nullJournalingServiceModel()
	imported.ID = types.StringValue("journal-id")
	imported.Description = types.StringValue("existing")
	imported.TransferProtocol = types.StringValue("smtp")
	var diagnostics diag.Diagnostics
	request := imported.updateRequest(context.Background(), imported, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("read-only imported state diagnostics: %v", diagnostics)
	}
	if body := requestJSONMap(t, request); len(body) != 0 {
		t.Fatalf("unchanged imported state produced PATCH body: %#v", body)
	}
}

func TestJournalingServiceResourceCreateAndUpdateReadAfterWrite(t *testing.T) {
	t.Parallel()

	var postCalls int
	var patchCalls int
	var getCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		switch request.Method {
		case http.MethodPost:
			postCalls++
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			smtp := body["smtpJournalingConnection"].(map[string]any)
			if smtp["password"] != "initial-password" {
				t.Fatalf("create body = %#v", body)
			}
			if _, present := body["pop3JournalingConnection"]; present {
				t.Fatalf("create body included POP3: %#v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"journal-id"}`))
		case http.MethodPatch:
			patchCalls++
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			expected := map[string]any{
				"description":              "updated journal",
				"smtpJournalingConnection": map[string]any{"password": "rotated-password"},
			}
			if !reflect.DeepEqual(body, expected) {
				t.Fatalf("update body = %#v, want %#v", body, expected)
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			getCalls++
			description := "smtp journal"
			if patchCalls > 0 {
				description = "updated journal"
			}
			_, _ = w.Write([]byte(`{
				"id":"journal-id","description":"` + description + `","enabled":true,"messageFormat":"exchange_env",
				"removeJournalHeaders":false,"journalNonInternalAddresses":false,"journalUnknownInternalAddresses":false,
				"transferProtocol":"smtp","queueSize":2,
				"smtpJournalingConnection":{"emailAddress":"journal@example.com","password":"server-secret","usesAuthentication":true,"usesTls":true,"prefersClearText":false,"extendedDeduplication":false,"deliveryWaitAttempts":3,"inactivityTimeout":180,"processInitialDelay":0,"hostnames":["journal.example"]},
				"statusInfo":{"lastReceivedDateTime":"2026-08-08T00:00:00Z","status":"ok"}
			}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	resourceInstance := &journalingServiceResource{client: apiClient}
	var schemaResponse resource.SchemaResponse
	resourceInstance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)

	planModel := nullJournalingServiceModel()
	planModel.Description = types.StringValue("smtp journal")
	planModel.TransferProtocol = types.StringValue("smtp")
	planModel.Enabled = types.BoolValue(true)
	planModel.MessageFormat = types.StringValue("exchange_env")
	planModel.SMTPEmailAddress = types.StringValue("journal@example.com")
	planModel.SMTPUsesAuthentication = types.BoolValue(true)
	planModel.SMTPPasswordWOVersion = types.Int64Value(1)
	planModel.SMTPUsesTLS = types.BoolValue(true)

	configModel := planModel
	configModel.SMTPPasswordWO = types.StringValue("initial-password")
	plan := journalingPlan(t, schemaResponse.Schema, planModel)
	config := journalingConfig(t, schemaResponse.Schema, configModel)
	createResponse := resource.CreateResponse{State: emptyDirectoryState(schemaResponse.Schema)}
	resourceInstance.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: config}, &createResponse)
	if createResponse.Diagnostics.HasError() {
		t.Fatalf("create diagnostics: %v", createResponse.Diagnostics)
	}
	var created journalingServiceResourceModel
	createResponse.Diagnostics.Append(createResponse.State.Get(context.Background(), &created)...)
	if createResponse.Diagnostics.HasError() {
		t.Fatalf("created state diagnostics: %v", createResponse.Diagnostics)
	}
	if created.ID.ValueString() != "journal-id" || created.Description.ValueString() != "smtp journal" || !created.SMTPPasswordWO.IsNull() || created.Status.ValueString() != "ok" {
		t.Fatalf("created state = %#v", created)
	}

	updatePlanModel := created
	updatePlanModel.Description = types.StringValue("updated journal")
	updatePlanModel.SMTPPasswordWOVersion = types.Int64Value(2)
	updateConfigModel := updatePlanModel
	updateConfigModel.SMTPPasswordWO = types.StringValue("rotated-password")
	updateResponse := resource.UpdateResponse{State: emptyDirectoryState(schemaResponse.Schema)}
	resourceInstance.Update(context.Background(), resource.UpdateRequest{
		Plan:   journalingPlan(t, schemaResponse.Schema, updatePlanModel),
		State:  createResponse.State,
		Config: journalingConfig(t, schemaResponse.Schema, updateConfigModel),
	}, &updateResponse)
	if updateResponse.Diagnostics.HasError() {
		t.Fatalf("update diagnostics: %v", updateResponse.Diagnostics)
	}
	var updated journalingServiceResourceModel
	updateResponse.Diagnostics.Append(updateResponse.State.Get(context.Background(), &updated)...)
	if updateResponse.Diagnostics.HasError() {
		t.Fatalf("updated state diagnostics: %v", updateResponse.Diagnostics)
	}
	if updated.Description.ValueString() != "updated journal" || !updated.SMTPPasswordWO.IsNull() || updated.SMTPPasswordWOVersion.ValueInt64() != 2 {
		t.Fatalf("updated state = %#v", updated)
	}
	if postCalls != 1 || patchCalls != 1 || getCalls != 2 {
		t.Fatalf("calls post=%d patch=%d get=%d", postCalls, patchCalls, getCalls)
	}
}

func TestJournalingServiceReadRemovesExternallyDeletedResource(t *testing.T) {
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
	resourceInstance := &journalingServiceResource{client: apiClient}
	var schemaResponse resource.SchemaResponse
	resourceInstance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	state := emptyDirectoryState(schemaResponse.Schema)
	if diagnostics := state.SetAttribute(context.Background(), path.Root("id"), "missing"); diagnostics.HasError() {
		t.Fatalf("state diagnostics: %v", diagnostics)
	}
	response := resource.ReadResponse{State: state}
	resourceInstance.Read(context.Background(), resource.ReadRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", response.Diagnostics)
	}
	if !response.State.Raw.IsNull() {
		t.Fatalf("state was not removed: %s", response.State.Raw.String())
	}
}

func nullJournalingServiceModel() journalingServiceResourceModel {
	return journalingServiceResourceModel{
		ID: types.StringNull(), Description: types.StringNull(), Enabled: types.BoolNull(), MessageFormat: types.StringNull(),
		RemoveJournalHeaders: types.BoolNull(), JournalNonInternalAddresses: types.BoolNull(), JournalUnknownInternalAddresses: types.BoolNull(), TransferProtocol: types.StringNull(),
		SMTPEmailAddress: types.StringNull(), SMTPIPRanges: types.ListNull(types.StringType), SMTPUsesAuthentication: types.BoolNull(), SMTPPasswordWO: types.StringNull(),
		SMTPPasswordWOVersion: types.Int64Null(), SMTPUsesTLS: types.BoolNull(), SMTPPrefersClearText: types.BoolNull(), SMTPExtendedDeduplication: types.BoolNull(),
		SMTPDeliveryWaitAttempts: types.Int64Null(), SMTPInactivityTimeout: types.Int64Null(), SMTPProcessInitialDelay: types.Int64Null(), SMTPHostnames: types.ListNull(types.StringType),
		POP3EmailAddress: types.StringNull(), POP3Mailbox: types.StringNull(), POP3PasswordWO: types.StringNull(), POP3PasswordWOVersion: types.Int64Null(),
		POP3Host: types.StringNull(), POP3Port: types.Int64Null(), POP3UsesPOP3S: types.BoolNull(), POP3EncryptionIsRelaxed: types.BoolNull(), POP3DetailedLoggingIsEnabled: types.BoolNull(),
		QueueSize: types.Int64Null(), Status: types.StringNull(), LastReceivedDateTime: types.StringNull(),
	}
}

func journalingPlan(t *testing.T, resourceSchema schema.Schema, model journalingServiceResourceModel) tfsdk.Plan {
	t.Helper()
	raw := journalingRawValue(t, resourceSchema, model)
	return tfsdk.Plan{Raw: raw, Schema: resourceSchema}
}

func journalingConfig(t *testing.T, resourceSchema schema.Schema, model journalingServiceResourceModel) tfsdk.Config {
	t.Helper()
	raw := journalingRawValue(t, resourceSchema, model)
	return tfsdk.Config{Raw: raw, Schema: resourceSchema}
}

func journalingRawValue(t *testing.T, resourceSchema schema.Schema, model journalingServiceResourceModel) tftypes.Value {
	t.Helper()
	state := emptyDirectoryState(resourceSchema)
	if diagnostics := state.Set(context.Background(), &model); diagnostics.HasError() {
		t.Fatalf("raw value diagnostics: %v", diagnostics)
	}
	return state.Raw
}
