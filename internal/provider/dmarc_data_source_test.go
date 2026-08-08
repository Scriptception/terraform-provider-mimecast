package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestDMARCInventoryDataSourceSchemasAreCompleteAndTyped(t *testing.T) {
	tests := []struct {
		constructor func() datasource.DataSource
		typeName    string
		attributes  []string
	}{
		{NewDMARCDomainsDataSource, "mimecast_dmarc_domains", []string{"dmarc_delegation_id", "dkim_delegation_id", "spf_delegation_id", "dns_txt_records", "dns_dkim_records"}},
		{NewDMARCDomainGroupsDataSource, "mimecast_dmarc_domain_groups", []string{"does_auto_include_org_subdomains", "include_domains_with_status", "included_domains", "include_domains_regex"}},
		{NewDMARCNotificationsDataSource, "mimecast_dmarc_notifications", []string{"emails", "domains", "groups", "invalid_message_threshold", "dns_dmarc_records"}},
		{NewDMARCDelegatedDomainsDataSource, "mimecast_dmarc_delegated_domains", []string{"hash", "dmarc_delegation_status", "dkim_delegation_status", "spf_delegation_status", "details"}},
		{NewDMARCPolicyPresetsDataSource, "mimecast_dmarc_policy_presets", []string{"rua_addresses", "ruf_addresses", "failure_reporting_options", "percentage"}},
		{NewDMARCUsersDataSource, "mimecast_dmarc_users", []string{"user_name", "user_email", "allowed_groups", "aggregate_reports", "vendor_management"}},
	}

	for _, test := range tests {
		t.Run(test.typeName, func(t *testing.T) {
			instance := test.constructor()
			var metadata datasource.MetadataResponse
			instance.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
			if metadata.TypeName != test.typeName {
				t.Fatalf("type name = %q", metadata.TypeName)
			}
			var response datasource.SchemaResponse
			instance.Schema(context.Background(), datasource.SchemaRequest{}, &response)
			if response.Diagnostics.HasError() {
				t.Fatal(response.Diagnostics)
			}
			items, ok := response.Schema.Attributes["items"].(dsschema.ListNestedAttribute)
			if !ok {
				t.Fatalf("items schema = %T", response.Schema.Attributes["items"])
			}
			for _, attribute := range test.attributes {
				if _, exists := items.NestedObject.Attributes[attribute]; !exists {
					t.Fatalf("items schema is missing %q", attribute)
				}
			}
			if _, rawJSON := items.NestedObject.Attributes["json"]; rawJSON {
				t.Fatal("data source exposes raw JSON")
			}
		})
	}
}

func TestDMARCInventoryDataSourcesPreserveOfficialResponseFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		if request.Method != http.MethodGet {
			http.NotFound(w, request)
			return
		}
		fixtures := map[string]string{
			"/dmarc-analyzer/v1/domains":             `{"items":[{"id":"domain-1","domain":"example.invalid","activityStatus":"active","dmarcDelegationId":"dmarc-1","dkimDelegationId":"dkim-1","spfDelegationId":"spf-1","dnsRecords":{"txt":[{"domain":"example.invalid","value":"v=DMARC1"}],"dkim":[{"domain":"selector._domainkey.example.invalid","selector":"selector","value":"key"}]}}]}`,
			"/dmarc-analyzer/v1/domain-groups":       `{"items":[{"id":"group-1","name":"Group","type":"dynamic","doesAutoIncludeOrgSubdomains":true,"includeDomainsWithStatus":"active","includedDomains":[{"id":"domain-1","domain":"example.invalid","name":"Example"}],"includeDomainsRegex":[".*\\.example\\.invalid"],"domainsCount":1}]}`,
			"/dmarc-analyzer/v1/notifications":       `{"items":[{"id":"notification-1","email":["alerts@example.invalid"],"frequency":"daily","type":"complianceMonitor","domains":[{"id":"domain-1","domain":"example.invalid"}],"groups":[{"id":"group-1","name":"Group"}],"triggerConfig":{"isIndividualDomainAlert":true,"invalidMessageTrigger":{"enabled":true,"threshold":10,"interval":"daily"},"dmarcComplianceTrigger":{"enabled":true,"threshold":90,"interval":"weekly"},"forensicMessageTrigger":{"enabled":false,"threshold":1,"interval":"monthly"},"dmarcRecords":true,"dkimRecords":false,"spfRecords":true},"nextTrigger":"2026-08-09T00:00:00Z"}]}`,
			"/dmarc-analyzer/v1/delegated-domains":   `{"items":[{"id":"domain-1","domain":"example.invalid","hash":"hash-1","dmarcDelegationStatus":"delegated","dmarcPolicy":"reject","dkimDelegationStatus":"delegated","spfDelegationStatus":"delegated","details":"ready"}]}`,
			"/dmarc-analyzer/v1/dmarc-policy-preset": `{"items":[{"id":"preset-1","name":"Strict","isDefaultPolicy":true,"description":"Strict policy","version":"DMARC1","policy":"reject","subdomainPolicy":"quarantine","ruaAddresses":["rua@example.invalid"],"rufAddresses":["ruf@example.invalid"],"dkimAlignment":"s","spfAlignment":"s","reportInterval":86400,"failureReportingOptions":"1:d:s","failureReportFormat":"afrf","percentage":100}]}`,
			"/dmarc-analyzer/v1/users":               `{"items":[{"id":"user-1","userName":"Terraform User","userEmail":"user@example.invalid","userPermission":"limited","allowedGroups":[{"id":"group-1","name":"Group","type":"static"}],"features":{"aggregateReports":true,"alertsAndNotifications":true,"dnsDelegation":true,"dnsChecker":true,"dnsGenerator":true,"domainManagement":true,"encryptionPgpKey":true,"forensicReports":true,"reporting":true,"taskManager":true,"timeline":true,"tlsReports":true,"userManagement":true,"vendorManagement":true}}]}`,
		}
		fixture, ok := fixtures[request.URL.Path]
		if !ok {
			http.NotFound(w, request)
			return
		}
		_, _ = w.Write([]byte(fixture))
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "secret", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}

	domainState := readDMARCDataSourceState(t, NewDMARCDomainsDataSource(), apiClient)
	var domains dmarcManagedDomainsDataSourceModel
	if diagnostics := domainState.Get(context.Background(), &domains); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(domains.Items) != 1 || domains.Items[0].DMARCDelegationID.ValueString() != "dmarc-1" || len(domains.Items[0].DNSTXT) != 1 || len(domains.Items[0].DNSDKIM) != 1 {
		t.Fatalf("domain state = %#v", domains)
	}

	groupState := readDMARCDataSourceState(t, NewDMARCDomainGroupsDataSource(), apiClient)
	var groups dmarcDomainGroupsDataSourceModel
	if diagnostics := groupState.Get(context.Background(), &groups); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(groups.Items) != 1 || !groups.Items[0].DoesAutoIncludeOrgSubdomains.ValueBool() || len(groups.Items[0].IncludedDomains) != 1 || len(groups.Items[0].IncludeDomainsRegex.Elements()) != 1 {
		t.Fatalf("group state = %#v", groups)
	}

	notificationState := readDMARCDataSourceState(t, NewDMARCNotificationsDataSource(), apiClient)
	var notifications dmarcNotificationsDataSourceModel
	if diagnostics := notificationState.Get(context.Background(), &notifications); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(notifications.Items) != 1 || len(notifications.Items[0].Emails.Elements()) != 1 || notifications.Items[0].InvalidMessageThreshold.ValueInt64() != 10 || !notifications.Items[0].DNSDMARCRecords.ValueBool() {
		t.Fatalf("notification state = %#v", notifications)
	}

	delegatedState := readDMARCDataSourceState(t, NewDMARCDelegatedDomainsDataSource(), apiClient)
	var delegated dmarcDelegatedDomainsDataSourceModel
	if diagnostics := delegatedState.Get(context.Background(), &delegated); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(delegated.Items) != 1 || delegated.Items[0].Hash.ValueString() != "hash-1" || delegated.Items[0].Details.ValueString() != "ready" {
		t.Fatalf("delegated state = %#v", delegated)
	}

	presetState := readDMARCDataSourceState(t, NewDMARCPolicyPresetsDataSource(), apiClient)
	var presets dmarcPolicyPresetsDataSourceModel
	if diagnostics := presetState.Get(context.Background(), &presets); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(presets.Items) != 1 || presets.Items[0].Percentage.ValueInt64() != 100 || presets.Items[0].FailureReportingOptions.ValueString() != "1:d:s" || len(presets.Items[0].RUAAddresses.Elements()) != 1 {
		t.Fatalf("preset state = %#v", presets)
	}

	userState := readDMARCDataSourceState(t, NewDMARCUsersDataSource(), apiClient)
	var users dmarcUsersDataSourceModel
	if diagnostics := userState.Get(context.Background(), &users); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(users.Items) != 1 || len(users.Items[0].AllowedGroups) != 1 || !users.Items[0].AggregateReports.ValueBool() || !users.Items[0].VendorManagement.ValueBool() {
		t.Fatalf("user state = %#v", users)
	}
}

func readDMARCDataSourceState(t *testing.T, instance datasource.DataSource, apiClient *client.Client) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	var schemaResponse datasource.SchemaResponse
	instance.Schema(ctx, datasource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatal(schemaResponse.Diagnostics)
	}
	state := tfsdk.State{
		Raw:    tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(ctx), nil),
		Schema: schemaResponse.Schema,
	}
	configured := instance.(*typedDataSource)
	configured.client = apiClient
	response := datasource.ReadResponse{State: state}
	configured.Read(ctx, datasource.ReadRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	return response.State
}
