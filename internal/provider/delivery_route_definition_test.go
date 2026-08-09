package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestDeliveryRouteDefinitionReadCanonicalisesAuthMechanisms(t *testing.T) {
	ctx := context.Background()
	remote := client.DeliveryRouteDefinition{SMTPAuth: &client.SMTPAuthentication{
		AuthMechanisms: []string{"  LOGIN ", "", "\t", "PLAIN"},
		Password:       "response-password-must-not-enter-state",
	}}

	model := deliveryRouteDefinitionModel{PasswordWO: types.StringNull()}
	var diagnostics diag.Diagnostics
	model.fromAPI(ctx, remote, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal("delivery route authentication mapping returned diagnostics")
	}
	var mechanisms []string
	if conversionDiagnostics := model.AuthMechanisms.ElementsAs(ctx, &mechanisms, false); conversionDiagnostics.HasError() {
		t.Fatal("delivery route authentication state could not be decoded")
	}
	if !reflect.DeepEqual(mechanisms, []string{"LOGIN", "PLAIN"}) {
		t.Fatalf("authentication mechanism order was not preserved: got %d entries", len(mechanisms))
	}
	if !model.PasswordWO.IsNull() {
		t.Fatal("response password entered resource state")
	}

	model.fromAPI(ctx, client.DeliveryRouteDefinition{SMTPAuth: &client.SMTPAuthentication{AuthMechanisms: []string{"", " \t "}}}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatal("blank authentication mechanism mapping returned diagnostics")
	}
	if !model.AuthMechanisms.IsNull() {
		t.Fatal("blank authentication mechanisms did not produce null resource state")
	}
}

func TestDeliveryRouteDefinitionsDataSourceCanonicalisesAuthMechanisms(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","expires_in":3600}`))
		case "/policy-management/cloud-gateway/v1/delivery-route/definitions":
			_, _ = w.Write([]byte(`{"definitions":[{"id":"route-1","description":"Primary","hostname":"mail.example.invalid","port":25,"smtpAuthentication":{"authMechanisms":[" LOGIN ","","  ","PLAIN"],"username":"smtp-user","password":"response-password-must-not-enter-state"}},{"id":"route-2","description":"Secondary","hostname":"backup.example.invalid","port":25,"smtpAuthentication":{"authMechanisms":["","\t"]}}],"meta":{}}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	apiClient, err := client.New(client.Config{BaseURL: server.URL, TokenURL: server.URL + "/oauth/token", ClientID: "id", ClientSecret: "test", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	instance := NewDeliveryRouteDefinitionsDataSource()
	state := readDMARCDataSourceState(t, instance, apiClient)
	var inventory deliveryRouteDefinitionsModel
	if diagnostics := state.Get(context.Background(), &inventory); diagnostics.HasError() {
		t.Fatal("delivery route inventory state could not be decoded")
	}
	if len(inventory.Items) != 2 {
		t.Fatalf("delivery route inventory returned %d items", len(inventory.Items))
	}
	var mechanisms []string
	if diagnostics := inventory.Items[0].AuthMechanisms.ElementsAs(context.Background(), &mechanisms, false); diagnostics.HasError() {
		t.Fatal("delivery route inventory authentication state could not be decoded")
	}
	if !reflect.DeepEqual(mechanisms, []string{"LOGIN", "PLAIN"}) {
		t.Fatalf("inventory authentication mechanism order was not preserved: got %d entries", len(mechanisms))
	}
	if !inventory.Items[1].AuthMechanisms.IsNull() {
		t.Fatal("blank authentication mechanisms did not produce null inventory state")
	}

	var schemaResponse datasource.SchemaResponse
	instance.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResponse)
	items, ok := schemaResponse.Schema.Attributes["items"].(dsschema.ListNestedAttribute)
	if !ok {
		t.Fatalf("delivery route inventory items schema has type %T", schemaResponse.Schema.Attributes["items"])
	}
	if _, exposed := items.NestedObject.Attributes["password"]; exposed {
		t.Fatal("delivery route inventory exposes an SMTP password")
	}
	username, ok := items.NestedObject.Attributes["username"].(dsschema.StringAttribute)
	if !ok || !username.Sensitive {
		t.Fatal("delivery route inventory username is not marked sensitive")
	}
}
