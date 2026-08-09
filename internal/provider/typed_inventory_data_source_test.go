package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestAccountGatewayAndUserInventorySchemasExcludeSensitiveFields(t *testing.T) {
	ctx := context.Background()
	schemaFor := func(constructor func() datasource.DataSource) dsschema.Schema {
		t.Helper()
		var response datasource.SchemaResponse
		constructor().Schema(ctx, datasource.SchemaRequest{}, &response)
		if response.Diagnostics.HasError() {
			t.Fatal(response.Diagnostics)
		}
		return response.Schema
	}

	account := schemaFor(NewAccountDataSource)
	for _, name := range []string{"admin_session_timeout", "content_administrator_default_view", "exgest_allow_extraction", "exgest_allow_query", "express_account", "max_retention_confirmed", "search_reason"} {
		if _, ok := account.Attributes[name]; !ok {
			t.Fatalf("account schema is missing %q", name)
		}
	}
	for _, name := range []string{"admin_email", "contact_email", "contact_name", "passphrase", "support_code", "telephone"} {
		if _, ok := account.Attributes[name]; ok {
			t.Fatalf("account schema exposes sensitive field %q", name)
		}
	}

	gateway := schemaFor(NewGatewayDetailsDataSource)
	for _, name := range []string{"outbound_enabled", "outbound_hostnames", "inbound_mx_records", "spf"} {
		if _, ok := gateway.Attributes[name]; !ok {
			t.Fatalf("gateway schema is missing %q", name)
		}
	}
	if _, ok := gateway.Attributes["umbrella_accounts"]; ok {
		t.Fatal("gateway schema exposes umbrella account identifiers")
	}
	mx, ok := gateway.Attributes["inbound_mx_records"].(dsschema.SingleNestedAttribute)
	if !ok || mx.Attributes["hostname"] == nil || mx.Attributes["priority"] == nil {
		t.Fatalf("inbound MX schema is incomplete: %T", gateway.Attributes["inbound_mx_records"])
	}

	users := schemaFor(NewUsersDataSource)
	items, ok := users.Attributes["items"].(dsschema.ListNestedAttribute)
	if !ok {
		t.Fatalf("users items schema = %T", users.Attributes["items"])
	}
	for _, name := range []string{"address_type", "is_alias"} {
		if _, ok := items.NestedObject.Attributes[name]; !ok {
			t.Fatalf("user schema is missing %q", name)
		}
	}
	for _, name := range []string{"alias_for", "source"} {
		if _, ok := items.NestedObject.Attributes[name]; ok {
			t.Fatalf("user schema exposes deferred field %q", name)
		}
	}
}

func TestAccountGatewayAndUserInventoryStatePreservesOfficialFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
		case "/api/account/get-account":
			_, _ = w.Write([]byte(`{"data":[{"adminSessionTimeout":30,"contentAdministratorDefaultView":"archive","exgestAllowExtraction":true,"exgestAllowQuery":false,"expressAccount":false,"maxRetentionConfirmed":true,"searchReason":true,"packages":[]}]}`))
		case "/email/cloud-gateway/v1/gateway-details":
			_, _ = w.Write([]byte(`{"outboundEnabled":true,"outboundHostnames":["mail.example.invalid"],"inboundMxRecords":{"hostname":"mx.example.invalid","priority":10},"spf":"v=spf1 -all"}`))
		case "/user/cloud-gateway/v1/users":
			_, _ = w.Write([]byte(`{"users":[{"id":"user-1","emailAddress":"user@example.invalid","addressType":"created_by_ldap_sync","isAlias":false}],"meta":{}}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "test", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var account accountModel
	if diagnostics := readDMARCDataSourceState(t, NewAccountDataSource(), apiClient).Get(ctx, &account); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if account.AdminSessionTimeout.ValueInt64() != 30 || account.ContentAdministratorDefaultView.ValueString() != "archive" || !account.ExgestAllowExtraction.ValueBool() || account.ExgestAllowQuery.ValueBool() || account.ExpressAccount.ValueBool() || !account.MaxRetentionConfirmed.ValueBool() || !account.SearchReason.ValueBool() {
		t.Fatalf("account state did not preserve official fields: %#v", account)
	}

	var gateway gatewayDetailsModel
	if diagnostics := readDMARCDataSourceState(t, NewGatewayDetailsDataSource(), apiClient).Get(ctx, &gateway); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var hostnames []string
	if diagnostics := gateway.OutboundHostnames.ElementsAs(ctx, &hostnames, false); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !gateway.OutboundEnabled.ValueBool() || len(hostnames) != 1 || hostnames[0] != "mail.example.invalid" || gateway.InboundMXRecords == nil || gateway.InboundMXRecords.Hostname.ValueString() != "mx.example.invalid" || gateway.InboundMXRecords.Priority.ValueFloat64() != 10 || gateway.SPF.ValueString() != "v=spf1 -all" {
		t.Fatalf("gateway state did not preserve official fields: %#v", gateway)
	}

	var users usersModel
	if diagnostics := readDMARCDataSourceState(t, NewUsersDataSource(), apiClient).Get(ctx, &users); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if len(users.Items) != 1 || users.Items[0].AddressType.ValueString() != "created_by_ldap_sync" || users.Items[0].IsAlias.ValueBool() {
		t.Fatalf("user state did not preserve official fields: %#v", users)
	}
}
