package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTypedInventoryDecodesOfficialAccountGatewayAndUserFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
		case "/api/account/get-account":
			_, _ = w.Write([]byte(`{"data":[{"adminSessionTimeout":30,"contentAdministratorDefaultView":"archive","exgestAllowExtraction":true,"exgestAllowQuery":false,"expressAccount":false,"maxRetentionConfirmed":true,"searchReason":true}]}`))
		case "/email/cloud-gateway/v1/gateway-details":
			_, _ = w.Write([]byte(`{"outboundEnabled":true,"outboundHostnames":["z.example.invalid","a.example.invalid"],"inboundMxRecords":{"hostname":"mx.example.invalid","priority":10},"spf":"v=spf1 -all"}`))
		case "/user/cloud-gateway/v1/users":
			_, _ = w.Write([]byte(`{"users":[{"id":"user-1","emailAddress":"user@example.invalid","addressType":"created_by_ldap_sync","isAlias":false,"source":"ldap"}],"meta":{}}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	apiClient, err := New(Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "test", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	account, err := apiClient.GetAccountSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if account.AdminSessionTimeout != 30 || account.ContentAdministratorDefaultView != "archive" || account.ExgestAllowExtraction == nil || !*account.ExgestAllowExtraction || account.ExgestAllowQuery == nil || *account.ExgestAllowQuery || account.ExpressAccount == nil || *account.ExpressAccount || account.MaxRetentionConfirmed == nil || !*account.MaxRetentionConfirmed || account.SearchReason == nil || !*account.SearchReason {
		t.Fatalf("account inventory fields were not decoded: %#v", account)
	}

	gateway, err := apiClient.GetGatewayDetails(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gateway.OutboundEnabled == nil || !*gateway.OutboundEnabled || len(gateway.OutboundHostnames) != 2 || gateway.OutboundHostnames[0] != "a.example.invalid" || gateway.InboundMXRecords == nil || gateway.InboundMXRecords.Hostname != "mx.example.invalid" || gateway.InboundMXRecords.Priority != 10 || gateway.SPF != "v=spf1 -all" {
		t.Fatalf("gateway inventory fields were not decoded: %#v", gateway)
	}

	users, err := apiClient.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].AddressType != "created_by_ldap_sync" || users[0].IsAlias == nil || *users[0].IsAlias {
		t.Fatalf("user inventory fields were not decoded: %#v", users)
	}
}
