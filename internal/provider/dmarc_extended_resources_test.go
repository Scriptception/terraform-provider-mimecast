package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestExtendedDMARCResourceConstructors(t *testing.T) {
	tests := []struct {
		constructor func() resource.Resource
		typeName    string
		attributes  []string
	}{
		{NewDMARCDelegatedDomainResource, "mimecast_dmarc_delegated_domain", []string{"managed_domain_id", "dmarc_delegation_status"}},
		{NewDMARCDomainGroupAssociationResource, "mimecast_dmarc_domain_group_association", []string{"group_id", "domain_id"}},
		{NewDMARCDefinitionResource, "mimecast_dmarc_definition", []string{"domain_id", "policy_preset_id", "record_value"}},
		{NewDMARCDKIMDefinitionResource, "mimecast_dmarc_dkim_definition", []string{"domain_id", "selector", "record_type"}},
		{NewDMARCSPFDefinitionResource, "mimecast_dmarc_spf_definition", []string{"domain_id", "terms", "all_qualifier"}},
		{NewDMARCUserResource, "mimecast_dmarc_user", []string{"user_email", "user_permission", "allowed_group_ids"}},
	}
	for _, test := range tests {
		t.Run(test.typeName, func(t *testing.T) {
			instance := test.constructor()
			if _, ok := instance.(resource.ResourceWithImportState); !ok {
				t.Fatal("resource does not implement import")
			}
			var metadata resource.MetadataResponse
			instance.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
			if metadata.TypeName != test.typeName {
				t.Fatalf("type name = %q", metadata.TypeName)
			}
			var response resource.SchemaResponse
			instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
			if response.Diagnostics.HasError() {
				t.Fatal(response.Diagnostics)
			}
			for _, attribute := range test.attributes {
				if _, exists := response.Schema.Attributes[attribute]; !exists {
					t.Fatalf("schema is missing %q", attribute)
				}
			}
			if _, rawJSON := response.Schema.Attributes["json"]; rawJSON {
				t.Fatal("resource exposes raw JSON")
			}
		})
	}
}

func TestReplaceOnlyDMARCIdentityFields(t *testing.T) {
	tests := []struct {
		resource  resource.Resource
		attribute string
	}{
		{NewDMARCDelegatedDomainResource(), "managed_domain_id"},
		{NewDMARCDomainGroupAssociationResource(), "group_id"},
		{NewDMARCDefinitionResource(), "policy_preset_id"},
		{NewDMARCDKIMDefinitionResource(), "selector"},
		{NewDMARCSPFDefinitionResource(), "domain_id"},
		{NewDMARCUserResource(), "user_email"},
	}
	for _, test := range tests {
		var response resource.SchemaResponse
		test.resource.Schema(context.Background(), resource.SchemaRequest{}, &response)
		attribute, ok := response.Schema.Attributes[test.attribute].(schema.StringAttribute)
		if !ok || len(attribute.PlanModifiers) == 0 {
			t.Fatalf("%T.%s does not require replacement", test.resource, test.attribute)
		}
	}
}

func TestDMARCDefinitionPresetIsOptionalForImport(t *testing.T) {
	instance := NewDMARCDefinitionResource().(resource.ResourceWithImportState)
	var schemaResponse resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)

	preset, ok := schemaResponse.Schema.Attributes["policy_preset_id"].(schema.StringAttribute)
	if !ok || !preset.Optional || preset.Required {
		t.Fatalf("policy_preset_id must be optional for imports: %#v", preset)
	}

	response := resource.ImportStateResponse{State: tfsdk.State{
		Raw: tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(context.Background()), nil), Schema: schemaResponse.Schema,
	}}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "domain-1"}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	var value types.String
	response.Diagnostics.Append(response.State.GetAttribute(context.Background(), path.Root("policy_preset_id"), &value)...)
	if response.Diagnostics.HasError() || !value.IsNull() {
		t.Fatalf("policy_preset_id = %#v, diagnostics = %v", value, response.Diagnostics)
	}
}

func TestDMARCDKIMCrossFieldValidation(t *testing.T) {
	tests := []struct {
		name      string
		model     dmarcDKIMDefinitionResourceModel
		wantError bool
	}{
		{
			name: "valid TXT",
			model: dmarcDKIMDefinitionResourceModel{RecordType: types.StringValue("txt"), Version: types.StringValue("DKIM1"),
				PublicKeyType: types.StringValue("rsa"), PublicKeyData: types.StringValue("public-key")},
		},
		{name: "TXT missing key", model: dmarcDKIMDefinitionResourceModel{RecordType: types.StringValue("txt"), Version: types.StringValue("DKIM1")}, wantError: true},
		{name: "valid CNAME", model: dmarcDKIMDefinitionResourceModel{RecordType: types.StringValue("cname"), Hostname: types.StringValue("dkim.example.invalid")}},
		{name: "CNAME missing hostname", model: dmarcDKIMDefinitionResourceModel{RecordType: types.StringValue("cname")}, wantError: true},
		{name: "CNAME with public key", model: dmarcDKIMDefinitionResourceModel{RecordType: types.StringValue("cname"), Hostname: types.StringValue("dkim.example.invalid"), PublicKeyType: types.StringValue("rsa")}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var diagnostics diag.Diagnostics
			validateDMARCDKIMModel(test.model, &diagnostics)
			if diagnostics.HasError() != test.wantError {
				t.Fatalf("diagnostics = %v, want error %v", diagnostics, test.wantError)
			}
		})
	}
}

func TestDMARCDomainGroupAssociationCompositeImport(t *testing.T) {
	instance := NewDMARCDomainGroupAssociationResource().(resource.ResourceWithImportState)
	var schemaResponse resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	response := resource.ImportStateResponse{State: tfsdk.State{
		Raw: tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(context.Background()), nil), Schema: schemaResponse.Schema,
	}}
	instance.ImportState(context.Background(), resource.ImportStateRequest{ID: "group-1/domain-1"}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	for attribute, expected := range map[string]string{"id": "group-1/domain-1", "group_id": "group-1", "domain_id": "domain-1"} {
		var value types.String
		response.Diagnostics.Append(response.State.GetAttribute(context.Background(), path.Root(attribute), &value)...)
		if response.Diagnostics.HasError() || value.ValueString() != expected {
			t.Fatalf("%s = %q, diagnostics = %v", attribute, value.ValueString(), response.Diagnostics)
		}
	}
}

func TestDMARCSPFTermsPreserveOrderAndTypes(t *testing.T) {
	ctx := context.Background()
	definition := client.ManagedDMARCSPFDefinition{
		Version: "v=spf1", AllQualifier: "-all",
		Terms: []client.ManagedDMARCSPFTerm{{Type: "include", Target: "first.invalid"}, {Type: "ip4", Target: "192.0.2.0", CIDRIPv4: int64PointerForTest(24)}},
	}
	model := dmarcSPFDefinitionResourceModel{DomainID: types.StringValue("domain-1")}
	var diagnostics diag.Diagnostics
	model.fromAPI(ctx, definition, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var terms []dmarcSPFTermModel
	diagnostics.Append(model.Terms.ElementsAs(ctx, &terms, false)...)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(terms) != 2 || terms[0].Target.ValueString() != "first.invalid" || terms[1].CIDRIPv4.ValueInt64() != 24 {
		t.Fatalf("terms = %#v", terms)
	}
	roundTrip := model.toAPI(ctx, &diagnostics)
	if diagnostics.HasError() || !reflect.DeepEqual(roundTrip, definition) {
		t.Fatalf("round trip = %#v, diagnostics = %v", roundTrip, diagnostics)
	}
}

func TestDMARCUserFeatureAndGroupRoundTrip(t *testing.T) {
	ctx := context.Background()
	trueValue := true
	model := dmarcUserResourceModel{}
	var diagnostics diag.Diagnostics
	model.fromAPI(ctx, client.ManagedDMARCUser{
		ID: "user-1", UserEmail: "user@example.invalid", UserPermission: "limited",
		AllowedGroups: []client.DMARCUserDomainGroup{{ID: "z"}, {ID: "a"}},
		Features:      &client.ManagedDMARCUserFeatures{DNSChecker: &trueValue},
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var groups []string
	diagnostics.Append(model.AllowedGroupIDs.ElementsAs(ctx, &groups, false)...)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !reflect.DeepEqual(groups, []string{"a", "z"}) || !model.DNSChecker.ValueBool() {
		t.Fatalf("groups = %#v, dns_checker = %#v", groups, model.DNSChecker)
	}
	request := model.toAPI(ctx, &diagnostics, false)
	if request.UserEmail != "" || request.Features == nil || request.Features.DNSChecker == nil || !*request.Features.DNSChecker {
		t.Fatalf("update request = %#v", request)
	}
}

func TestDMARCVendorsDataSourceSchema(t *testing.T) {
	instance := NewDMARCVendorsDataSource()
	var metadata datasource.MetadataResponse
	instance.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
	if metadata.TypeName != "mimecast_dmarc_vendors" {
		t.Fatalf("type name = %q", metadata.TypeName)
	}
	var response datasource.SchemaResponse
	instance.Schema(context.Background(), datasource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	if _, exists := response.Schema.Attributes["vendor_id"]; !exists {
		t.Fatal("vendor_id detail filter is missing")
	}
	if _, exists := response.Schema.Attributes["items"]; !exists {
		t.Fatal("typed vendor items are missing")
	}
}

func int64PointerForTest(value int64) *int64 { return &value }
