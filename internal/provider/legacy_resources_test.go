package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestLifecycleResourceConstructorsAreTypedUniqueAndImportable(t *testing.T) {
	constructors := []func() resource.Resource{
		NewGreylistingPolicyResource,
		NewDeliveryRoutePolicyResource,
		NewAntiSpoofingPolicyResource,
		NewAntiSpoofingBypassPolicyResource,
		NewBlockedSenderPolicyResource,
		NewDNSAuthenticationOutboundPolicyResource,
		NewDeliveryRouteDefinitionResource,
		NewDNSAuthenticationOutboundDefinitionResource,
		NewManagedURLResource,
		NewProfileGroupResource,
		NewProfileGroupMemberResource,
		NewOutboundIPAddressesResource,
		NewCloudIntegratedPolicyResource,
		NewAddressAlterationDefinitionResource,
		NewAddressAlterationPolicyResource,
		NewWebSecurityURLPolicyResource,
		NewThreatReportingSubscriptionResource,
	}
	wantNew := map[string]bool{
		"mimecast_address_alteration_definition": false,
		"mimecast_address_alteration_policy":     false,
		"mimecast_web_security_url_policy":       false,
		"mimecast_threat_reporting_subscription": false,
	}
	names := make(map[string]bool, len(constructors))
	for _, constructor := range constructors {
		instance := constructor()
		var metadata resource.MetadataResponse
		instance.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		if metadata.TypeName == "" || names[metadata.TypeName] {
			t.Fatalf("invalid or duplicate resource type name %q", metadata.TypeName)
		}
		names[metadata.TypeName] = true
		if _, ok := wantNew[metadata.TypeName]; ok {
			wantNew[metadata.TypeName] = true
		}
		var schemaResponse resource.SchemaResponse
		instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
		if schemaResponse.Diagnostics.HasError() {
			t.Fatalf("schema diagnostics for %q: %v", metadata.TypeName, schemaResponse.Diagnostics)
		}
		if _, ok := schemaResponse.Schema.Attributes["id"]; !ok {
			t.Fatalf("resource %q has no typed id attribute", metadata.TypeName)
		}
		if _, rawJSON := schemaResponse.Schema.Attributes["json"]; rawJSON {
			t.Fatalf("resource %q exposes raw JSON", metadata.TypeName)
		}
		if _, ok := instance.(resource.ResourceWithImportState); !ok {
			t.Fatalf("resource %q is not importable", metadata.TypeName)
		}
	}
	for name, found := range wantNew {
		if !found {
			t.Fatalf("new resource constructor %q was not found", name)
		}
	}
}

func TestAddressAlterationDefinitionIsImmutable(t *testing.T) {
	instance := NewAddressAlterationDefinitionResource()
	var response resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	for _, name := range []string{"folder_id", "address_type", "original_address", "new_address", "routing"} {
		attribute, ok := response.Schema.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s is not a string attribute", name)
		}
		if len(attribute.PlanModifiers) == 0 {
			t.Fatalf("%s does not require replacement", name)
		}
	}
}

func TestAddressAlterationSetsDataSourceIsTypedReadOnlyInventory(t *testing.T) {
	instance := NewAddressAlterationSetsDataSource()
	var metadata datasource.MetadataResponse
	instance.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
	if metadata.TypeName != "mimecast_address_alteration_sets" {
		t.Fatalf("TypeName = %q", metadata.TypeName)
	}
	var response datasource.SchemaResponse
	instance.Schema(context.Background(), datasource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	for _, name := range []string{"id", "folder_id", "depth", "items"} {
		if _, ok := response.Schema.Attributes[name]; !ok {
			t.Fatalf("missing typed data-source attribute %q", name)
		}
	}
	if _, rawJSON := response.Schema.Attributes["json"]; rawJSON {
		t.Fatal("Address Alteration Set data source exposes raw JSON")
	}
}

func TestLegacyInventoryDataSourcesAreTyped(t *testing.T) {
	tests := []struct {
		constructor func() datasource.DataSource
		name        string
		itemFields  []string
	}{
		{NewAddressAlterationDefinitionsDataSource, "mimecast_address_alteration_definitions", []string{"id", "folder_id", "address_type", "original_address", "new_address", "routing"}},
		{NewAddressAlterationPoliciesDataSource, "mimecast_address_alteration_policies", []string{"id", "address_alteration_set_id", "policy"}},
		{NewThreatReportingSubscriptionsDataSource, "mimecast_threat_reporting_subscriptions", []string{"id", "notification_url", "resource_type", "creation_date_time", "expiration_date_time"}},
	}
	for _, test := range tests {
		instance := test.constructor()
		var metadata datasource.MetadataResponse
		instance.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		if metadata.TypeName != test.name {
			t.Fatalf("TypeName = %q, want %q", metadata.TypeName, test.name)
		}
		var response datasource.SchemaResponse
		instance.Schema(context.Background(), datasource.SchemaRequest{}, &response)
		if response.Diagnostics.HasError() {
			t.Fatal(response.Diagnostics)
		}
		if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
			t.Fatalf("%s schema implementation diagnostics: %v", test.name, diagnostics)
		}
		items, ok := response.Schema.Attributes["items"].(dsschema.ListNestedAttribute)
		if !ok || !items.Computed {
			t.Fatalf("%s items = %#v", test.name, response.Schema.Attributes["items"])
		}
		for _, field := range test.itemFields {
			if _, ok := items.NestedObject.Attributes[field]; !ok {
				t.Fatalf("%s item missing %q", test.name, field)
			}
		}
		if _, hasClientState := items.NestedObject.Attributes["client_state"]; hasClientState {
			t.Fatalf("%s exposes client state", test.name)
		}
	}
}

func TestJournalingAndConnectorInventorySchemasKeepPublicFields(t *testing.T) {
	tests := []struct {
		constructor func() datasource.DataSource
		fields      []string
	}{
		{NewJournalingServicesDataSource, []string{
			"smtp_email_address", "smtp_ip_ranges", "smtp_uses_authentication", "smtp_uses_tls", "smtp_prefers_clear_text", "smtp_extended_deduplication",
			"smtp_delivery_wait_attempts", "smtp_inactivity_timeout", "smtp_process_initial_delay", "smtp_hostnames", "pop3_email_address", "pop3_mailbox",
			"pop3_host", "pop3_port", "pop3_uses_pop3s", "pop3_encryption_is_relaxed", "pop3_detailed_logging_is_enabled", "status", "last_received_date_time",
		}},
		{NewConnectorsDataSource, []string{"product_id", "product_name", "product_code", "product_description"}},
	}
	for _, test := range tests {
		instance := test.constructor()
		var response datasource.SchemaResponse
		instance.Schema(context.Background(), datasource.SchemaRequest{}, &response)
		if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
			t.Fatalf("inventory schema implementation diagnostics: %v", diagnostics)
		}
		items := response.Schema.Attributes["items"].(dsschema.ListNestedAttribute)
		for _, field := range test.fields {
			if _, ok := items.NestedObject.Attributes[field]; !ok {
				t.Fatalf("inventory item missing %q", field)
			}
		}
		for _, forbidden := range []string{"password", "smtp_password", "pop3_password"} {
			if _, ok := items.NestedObject.Attributes[forbidden]; ok {
				t.Fatalf("inventory item exposes %q", forbidden)
			}
		}
	}
}

func TestProfileGroupMembersInventoryKeepsNote(t *testing.T) {
	instance := NewProfileGroupMembersDataSource()
	var response datasource.SchemaResponse
	instance.Schema(context.Background(), datasource.SchemaRequest{}, &response)
	items := response.Schema.Attributes["items"].(dsschema.ListNestedAttribute)
	if _, ok := items.NestedObject.Attributes["note"]; !ok {
		t.Fatal("profile group member inventory item is missing note")
	}

	model := groupMemberItemFromAPI(client.GroupMember{EmailAddress: "member@example.test", Note: "Managed by directory sync"})
	if model.Note.ValueString() != "Managed by directory sync" {
		t.Fatalf("note = %q", model.Note.ValueString())
	}
}

func TestWebSecurityURLPolicySchemaHasTypedTargetsAndActions(t *testing.T) {
	instance := NewWebSecurityURLPolicyResource()
	var response resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
		t.Fatalf("Web Security resource schema implementation diagnostics: %v", diagnostics)
	}
	targets, ok := response.Schema.Attributes["targets"].(schema.ListNestedAttribute)
	if !ok || !targets.Required {
		t.Fatalf("targets schema = %#v", response.Schema.Attributes["targets"])
	}
	if _, ok := targets.NestedObject.Attributes["policy"].(schema.SingleNestedAttribute); !ok {
		t.Fatal("targets do not contain a typed policy object")
	}
	actions, ok := response.Schema.Attributes["url_actions"].(schema.ListNestedAttribute)
	if !ok || !actions.Required {
		t.Fatalf("url_actions schema = %#v", response.Schema.Attributes["url_actions"])
	}
	for _, name := range []string{"id", "action", "type", "value"} {
		if _, ok := actions.NestedObject.Attributes[name]; !ok {
			t.Fatalf("url_actions missing %q", name)
		}
	}
}

func TestThreatReportingClientStateIsWriteOnlySensitive(t *testing.T) {
	instance := NewThreatReportingSubscriptionResource()
	var response resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	for _, name := range []string{"client_state_wo", "old_client_state_wo"} {
		attribute, ok := response.Schema.Attributes[name].(schema.StringAttribute)
		if !ok || !attribute.WriteOnly || !attribute.Sensitive || !attribute.Optional || attribute.Computed {
			t.Fatalf("%s must be optional, sensitive, write-only, and not computed: %#v", name, attribute)
		}
	}
	notificationURL := response.Schema.Attributes["notification_url"].(schema.StringAttribute)
	if len(notificationURL.PlanModifiers) == 0 {
		t.Fatal("notification_url must require replacement")
	}
}

func TestHTTPSURLValidatorRejectsNonHTTPS(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "https://callback.example.test/mimecast", valid: true},
		{value: "http://callback.example.test/mimecast", valid: false},
		{value: "not-a-url", valid: false},
	} {
		var response validator.StringResponse
		httpsURLValidator{}.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(test.value)}, &response)
		if response.Diagnostics.HasError() == test.valid {
			t.Fatalf("value %q valid=%t diagnostics=%v", test.value, test.valid, response.Diagnostics)
		}
	}
}

func TestWebSecurityReadPreservesConfiguredListIdentity(t *testing.T) {
	model := webSecurityURLPolicyModel{
		Targets: []webSecurityTargetModel{
			{Policy: identityPolicyModel("B")},
			{Policy: identityPolicyModel("A")},
		},
		URLActions: []webSecurityURLActionModel{
			{Action: types.StringValue("block"), Type: types.StringValue("url"), Value: types.StringValue("https://b.example.test")},
			{Action: types.StringValue("allow"), Type: types.StringValue("domain"), Value: types.StringValue("a.example.test")},
		},
	}
	remote := client.WebSecurityURLPolicy{
		ID: "web-1", Description: "test",
		Policies: []client.WebSecurityTargetPolicy{
			{ID: "target-a", Policy: identityClientPolicy("A")},
			{ID: "target-b", Policy: identityClientPolicy("B")},
		},
		URLs: []client.WebSecurityURLAction{
			{ID: "url-a", Action: "allow", Type: "domain", Value: "a.example.test"},
			{ID: "url-b", Action: "block", Type: "url", Value: "https://b.example.test"},
		},
	}
	var diagnostics diag.Diagnostics
	model.fromAPI(context.Background(), remote, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(model.Targets) != 2 || model.Targets[0].Policy.Description.ValueString() != "B" || model.Targets[0].ID.ValueString() != "target-b" || model.Targets[1].ID.ValueString() != "target-a" {
		t.Fatalf("targets = %#v", model.Targets)
	}
	if len(model.URLActions) != 2 || model.URLActions[0].ID.ValueString() != "url-b" || model.URLActions[1].ID.ValueString() != "url-a" {
		t.Fatalf("url_actions = %#v", model.URLActions)
	}
}

func TestThreatReportingReadPreservesUnreturnedNotificationURL(t *testing.T) {
	model := threatReportingSubscriptionModel{
		NotificationURL:      types.StringValue("https://callback.example.test/mimecast"),
		ClientStateWO:        types.StringValue("new-client-state"),
		OldClientStateWO:     types.StringValue("old-client-state"),
		ClientStateWOVersion: types.Int64Value(7),
	}
	model.fromAPI(client.ThreatReportingSubscription{SubscriptionID: "subscription-1", ResourceType: "threat-analysis"})
	if model.NotificationURL.ValueString() != "https://callback.example.test/mimecast" {
		t.Fatalf("notification_url = %q", model.NotificationURL.ValueString())
	}
	if !model.ClientStateWO.IsNull() || !model.OldClientStateWO.IsNull() {
		t.Fatalf("write-only client state was retained: %#v / %#v", model.ClientStateWO, model.OldClientStateWO)
	}
	if model.ClientStateWOVersion.ValueInt64() != 7 {
		t.Fatalf("client_state_wo_version = %d", model.ClientStateWOVersion.ValueInt64())
	}
}

func TestDeliveryRoutePasswordRequiresVersionChange(t *testing.T) {
	ctx := context.Background()
	plan := deliveryRouteDefinitionModel{
		ID:              types.StringValue("route-1"),
		Description:     types.StringValue("route"),
		Hostname:        types.StringValue("mail.example.test"),
		Port:            types.Int64Value(25),
		AuthMechanisms:  types.ListNull(types.StringType),
		Username:        types.StringValue("smtp-user"),
		PasswordWO:      types.StringValue("replacement-password"),
		PasswordVersion: types.Int64Value(1),
	}
	prior := deliveryRouteDefinitionModel{PasswordVersion: types.Int64Value(1)}

	var diagnostics diag.Diagnostics
	unchanged := plan.updateAPI(ctx, prior, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if unchanged.SMTPAuth == nil || unchanged.SMTPAuth.Password != "" {
		t.Fatalf("unchanged version resent password: %#v", unchanged.SMTPAuth)
	}

	plan.PasswordVersion = types.Int64Value(2)
	diagnostics = nil
	changed := plan.updateAPI(ctx, prior, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if changed.SMTPAuth == nil || changed.SMTPAuth.Password != "replacement-password" {
		t.Fatalf("changed version did not send password: %#v", changed.SMTPAuth)
	}

	plan.PasswordWO = types.StringNull()
	diagnostics = nil
	_ = plan.updateAPI(ctx, prior, &diagnostics)
	if !diagnostics.HasError() {
		t.Fatal("version change without password_wo must be rejected")
	}
}

func TestCloudIntegratedSchemasAreFullyTyped(t *testing.T) {
	instance := NewCloudIntegratedPolicyResource()
	var response resource.SchemaResponse
	instance.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
		t.Fatalf("Cloud Integrated resource schema implementation diagnostics: %v", diagnostics)
	}
	for _, name := range []string{"targets_json", "actions_json", "alerts_json", "security_engines_json"} {
		if _, ok := response.Schema.Attributes[name]; ok {
			t.Fatalf("Cloud Integrated resource still exposes %q", name)
		}
	}
	for _, name := range []string{"targets", "actions", "alerts", "security_engines"} {
		if _, ok := response.Schema.Attributes[name].(schema.SingleNestedAttribute); !ok {
			t.Fatalf("%s is not a typed nested attribute: %#v", name, response.Schema.Attributes[name])
		}
	}
	targets := response.Schema.Attributes["targets"].(schema.SingleNestedAttribute)
	assertAttributeNames(t, targets.Attributes, "senders", "recipients", "exceptions", "address_match")
	senders := targets.Attributes["senders"].(schema.SingleNestedAttribute)
	assertAttributeNames(t, senders.Attributes, "route", "emails", "group_ids", "domains")
	securityEngines := response.Schema.Attributes["security_engines"].(schema.SingleNestedAttribute)
	assertAttributeNames(t, securityEngines.Attributes, "url_click", "phishing", "impersonation", "attachments")
	urlClick := securityEngines.Attributes["url_click"].(schema.SingleNestedAttribute)
	assertAttributeNames(t, urlClick.Attributes,
		"sensitivity", "scan_urls_in_attachment", "rewrite_enabled", "rewrite_mode", "force_secure_connection", "block_dangerous_extensions", "user_identification",
		"bi_unclassified_urls", "bi_admin_viewing", "bi_enter_text", "bi_paste_text", "bi_copy_text", "scan_outbound_emails")

	defaultPolicy := NewCloudIntegratedDefaultPolicyDataSource()
	var defaultResponse datasource.SchemaResponse
	defaultPolicy.Schema(context.Background(), datasource.SchemaRequest{}, &defaultResponse)
	if defaultResponse.Diagnostics.HasError() {
		t.Fatal(defaultResponse.Diagnostics)
	}
	if diagnostics := defaultResponse.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
		t.Fatalf("Cloud Integrated default-policy schema implementation diagnostics: %v", diagnostics)
	}
	for _, name := range []string{"targets", "actions", "alerts", "security_engines"} {
		if _, ok := defaultResponse.Schema.Attributes[name].(dsschema.SingleNestedAttribute); !ok {
			t.Fatalf("default policy %s is not a typed nested attribute: %#v", name, defaultResponse.Schema.Attributes[name])
		}
	}
}

func TestCloudIntegratedModelRoundTripsTypedContract(t *testing.T) {
	ctx := context.Background()
	enabled := true
	disabled := false
	threshold := int64(87)
	remote := client.CloudIntegratedPolicy{
		PolicyID: "policy-1", AccountID: "account-1", Name: "policy", Description: "typed", ProtectionMode: "ACTIVE",
		Targets: &client.CloudIntegratedTargets{
			Senders:    &client.CloudIntegratedRouteTarget{Route: "ALL", Emails: []string{"z@example.test", "a@example.test"}, Groups: []client.CloudIntegratedGroup{{ID: "group-z"}, {ID: "group-a"}}, Domains: []string{"z.example.test", "a.example.test"}},
			Recipients: &client.CloudIntegratedRouteTarget{Route: "INTERNAL"}, Exceptions: &client.CloudIntegratedException{Domains: []string{"exception.example.test"}}, AddressMatch: "BOTH",
		},
		Actions: &client.CloudIntegratedActions{Malware: "BLOCK", Phishing: "QUARANTINE", Untrustworthy: "MOVE_TO_JUNK", Spam: "DO_NOTHING"},
		Alerts:  &client.CloudIntegratedAlerts{Malware: &enabled, Phishing: &disabled, Untrustworthy: &enabled, Spam: &disabled},
		SecurityEngines: &client.CloudIntegratedSecurityEngines{
			URLClick:      &client.CloudIntegratedURLClickEngine{Sensitivity: "HIGH", RewriteEnabled: &enabled, BIAdminViewing: &disabled, UserIdentification: "ADV_SSO"},
			Phishing:      &client.CloudIntegratedPhishingEngine{SensitivityPhishingHigh: &threshold, ScanOutboundEmails: &enabled},
			Impersonation: &client.CloudIntegratedImpersonationEngine{CodeBreakerStatus: "ENABLED", ReportingStatus: "LEARNING", SilencerStatus: "DISABLED"},
			Attachments:   &client.CloudIntegratedAttachmentsEngine{SandboxEnabled: &enabled, UnreadableArchives: "QUARANTINE"},
		},
	}
	var model cloudIntegratedPolicyModel
	var diagnostics diag.Diagnostics
	model.fromAPI(ctx, remote, &diagnostics)
	roundTrip := model.toAPI(ctx, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if roundTrip.PolicyID != "" || roundTrip.AccountID != "" {
		t.Fatalf("write model included response-only fields: policyId=%q accountId=%q", roundTrip.PolicyID, roundTrip.AccountID)
	}
	if roundTrip.Targets == nil || roundTrip.Targets.Senders == nil || !reflect.DeepEqual(roundTrip.Targets.Senders.Emails, []string{"a@example.test", "z@example.test"}) {
		t.Fatalf("round-trip senders = %#v", roundTrip.Targets)
	}
	if len(roundTrip.Targets.Senders.Groups) != 2 || roundTrip.Targets.Senders.Groups[0].ID != "group-a" || roundTrip.SecurityEngines == nil || roundTrip.SecurityEngines.Phishing == nil || roundTrip.SecurityEngines.Phishing.SensitivityPhishingHigh == nil || *roundTrip.SecurityEngines.Phishing.SensitivityPhishingHigh != threshold {
		t.Fatalf("round-trip typed contract = %#v", roundTrip)
	}
	if model.TargetsSHA256.IsNull() || model.ActionsSHA256.IsNull() || model.AlertsSHA256.IsNull() || model.SecurityEnginesSHA256.IsNull() {
		t.Fatalf("canonical fingerprints not populated: %#v", model)
	}
}

func assertAttributeNames(t *testing.T, attributes map[string]schema.Attribute, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, ok := attributes[name]; !ok {
			t.Fatalf("missing typed attribute %q", name)
		}
	}
}

func identityPolicyModel(description string) legacyPolicyModel {
	return legacyPolicyModel{
		Description: types.StringValue(description),
		From:        legacyPolicyTargetModel{Type: types.StringValue("everyone")},
		To:          legacyPolicyTargetModel{Type: types.StringValue("everyone")},
	}
}

func identityClientPolicy(description string) client.LegacyPolicyScope {
	return client.LegacyPolicyScope{Description: description, From: client.LegacyPolicyTarget{Type: "everyone"}, To: client.LegacyPolicyTarget{Type: "everyone"}}
}
