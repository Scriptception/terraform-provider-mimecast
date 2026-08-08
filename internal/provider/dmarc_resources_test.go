package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestDMARCResourceConstructorsExposeTypedImportableSchemas(t *testing.T) {
	tests := []struct {
		name        string
		constructor func() resource.Resource
		typeName    string
		required    []string
	}{
		{"managed domain", NewDMARCManagedDomainResource, "mimecast_dmarc_managed_domain", []string{"id", "domain", "activity_status", "dns_dmarc_records"}},
		{"domain group", NewDMARCDomainGroupResource, "mimecast_dmarc_domain_group", []string{"id", "name", "type", "included_domain_ids"}},
		{"notification", NewDMARCNotificationResource, "mimecast_dmarc_notification", []string{"id", "type", "emails", "dns_dmarc_records"}},
		{"policy preset", NewDMARCPolicyPresetResource, "mimecast_dmarc_policy_preset", []string{"id", "name", "policy", "failure_reporting_options"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance := test.constructor()
			if _, ok := instance.(resource.ResourceWithImportState); !ok {
				t.Fatal("resource does not implement import")
			}
			var metadata resource.MetadataResponse
			instance.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
			if metadata.TypeName != test.typeName {
				t.Fatalf("type name = %q, want %q", metadata.TypeName, test.typeName)
			}
			var response resource.SchemaResponse
			instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
			if response.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", response.Diagnostics)
			}
			for _, name := range test.required {
				if _, ok := response.Schema.Attributes[name]; !ok {
					t.Fatalf("schema does not contain %q", name)
				}
			}
			if _, rawJSON := response.Schema.Attributes["json"]; rawJSON {
				t.Fatal("resource exposes raw JSON")
			}
		})
	}
}

func TestDMARCImmutableFieldsRequireReplacement(t *testing.T) {
	var domainSchema resource.SchemaResponse
	NewDMARCManagedDomainResource().Schema(context.Background(), resource.SchemaRequest{}, &domainSchema)
	domain, ok := domainSchema.Schema.Attributes["domain"].(schema.StringAttribute)
	if !ok || !domain.Required || len(domain.PlanModifiers) == 0 {
		t.Fatalf("domain attribute = %#v, want required replacement semantics", domain)
	}

	var notificationSchema resource.SchemaResponse
	NewDMARCNotificationResource().Schema(context.Background(), resource.SchemaRequest{}, &notificationSchema)
	notificationType, ok := notificationSchema.Schema.Attributes["type"].(schema.StringAttribute)
	if !ok || !notificationType.Required || len(notificationType.PlanModifiers) == 0 {
		t.Fatalf("notification type attribute = %#v, want required replacement semantics", notificationType)
	}

	var presetSchema resource.SchemaResponse
	NewDMARCPolicyPresetResource().Schema(context.Background(), resource.SchemaRequest{}, &presetSchema)
	_, ok = presetSchema.Schema.Attributes["failure_reporting_options"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("failure_reporting_options type = %T, want string", presetSchema.Schema.Attributes["failure_reporting_options"])
	}
}

func TestDMARCNotificationCrossFieldValidation(t *testing.T) {
	tests := []struct {
		name      string
		model     dmarcNotificationResourceModel
		wantError bool
	}{
		{
			name:      "DNS field rejected for summary",
			model:     dmarcNotificationResourceModel{Type: types.StringValue("dmarcSummary"), DNSDMARCRecords: types.BoolValue(true)},
			wantError: true,
		},
		{
			name:      "compliance field rejected for DNS monitor",
			model:     dmarcNotificationResourceModel{Type: types.StringValue("dnsMonitor"), InvalidMessageThreshold: types.Int64Value(10)},
			wantError: true,
		},
		{
			name:      "DNS fields accepted for DNS monitor",
			model:     dmarcNotificationResourceModel{Type: types.StringValue("dnsMonitor"), DNSDMARCRecords: types.BoolValue(true)},
			wantError: false,
		},
		{
			name:      "compliance fields accepted for compliance monitor",
			model:     dmarcNotificationResourceModel{Type: types.StringValue("complianceMonitor"), InvalidMessageThreshold: types.Int64Value(10)},
			wantError: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var diagnostics diag.Diagnostics
			validateDMARCNotificationModel(test.model, &diagnostics)
			if diagnostics.HasError() != test.wantError {
				t.Fatalf("diagnostics = %v, want error %v", diagnostics, test.wantError)
			}
		})
	}
}

func TestDMARCResourceModelsCanonicalizeSets(t *testing.T) {
	ctx := context.Background()
	group := dmarcDomainGroupResourceModel{}
	var diagnostics diag.Diagnostics
	group.fromAPI(ctx, client.ManagedDMARCDomainGroup{
		ID: "group-1", Name: "Terraform", Type: "static",
		IncludedDomains:     []client.DMARCDomainReference{{ID: "z"}, {ID: "a"}},
		IncludeDomainsRegex: []string{"z.*", "a.*"},
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var included []string
	diagnostics.Append(group.IncludedDomainIDs.ElementsAs(ctx, &included, false)...)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !reflect.DeepEqual(included, []string{"a", "z"}) {
		t.Fatalf("included IDs = %#v", included)
	}

	rua, ruf := []string{"z@example.invalid", "a@example.invalid"}, []string{"y@example.invalid", "b@example.invalid"}
	preset := dmarcPolicyPresetResourceModel{}
	preset.fromAPI(ctx, client.ManagedDMARCPolicyPreset{
		ID: "preset-1", Name: "Terraform",
		ManagedDMARCDefinition: client.ManagedDMARCDefinition{Version: "DMARC1", Policy: "none", RUAAddresses: &rua, RUFAddresses: &ruf},
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var addresses []string
	diagnostics.Append(preset.RUAAddresses.ElementsAs(ctx, &addresses, false)...)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !reflect.DeepEqual(addresses, []string{"a@example.invalid", "z@example.invalid"}) {
		t.Fatalf("RUA addresses = %#v", addresses)
	}
}

func TestDMARCDNSRecordsRemainTyped(t *testing.T) {
	ctx := context.Background()
	set, diagnostics := dmarcDNSRecordSet(ctx, []client.DMARCDNSRecordValue{
		{Domain: "a.example.invalid", Value: "192.0.2.1"},
	})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !reflect.DeepEqual(set.ElementType(ctx), dmarcDNSRecordObjectType) {
		t.Fatalf("element type = %#v, want typed DNS record object", set.ElementType(ctx))
	}
	var records []dmarcDNSRecordModel
	diagnostics.Append(set.ElementsAs(ctx, &records, false)...)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(records) != 1 || records[0].Domain.ValueString() != "a.example.invalid" {
		t.Fatalf("records = %#v", records)
	}
}

func TestDMARCEmailValidator(t *testing.T) {
	tests := []struct {
		value     string
		wantError bool
	}{
		{"alerts@example.invalid", false},
		{"Display Name <alerts@example.invalid>", true},
		{"not-an-email", true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			var response validator.StringResponse
			dmarcEmailValidator{}.ValidateString(context.Background(), validator.StringRequest{
				ConfigValue: types.StringValue(test.value), Path: path.Root("emails"),
			}, &response)
			if response.Diagnostics.HasError() != test.wantError {
				t.Fatalf("diagnostics = %v, want error %v", response.Diagnostics, test.wantError)
			}
		})
	}
}
