package provider

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestSensitiveValidatorInventory(t *testing.T) {
	ctx := context.Background()
	paths := make([]string, 0, 7)

	var providerSchema frameworkprovider.SchemaResponse
	New("test")().Schema(ctx, frameworkprovider.SchemaRequest{}, &providerSchema)
	for name, raw := range providerSchema.Schema.Attributes {
		if attribute, ok := raw.(providerschema.StringAttribute); ok && attribute.Sensitive && len(attribute.Validators) > 0 {
			paths = append(paths, "provider.mimecast."+name)
		}
	}

	for _, factory := range New("test")().Resources(ctx) {
		instance := factory()
		var metadata resource.MetadataResponse
		instance.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		var schemaResponse resource.SchemaResponse
		instance.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
		for name, raw := range schemaResponse.Schema.Attributes {
			switch attribute := raw.(type) {
			case resourceschema.StringAttribute:
				if attribute.Sensitive && len(attribute.Validators) > 0 {
					paths = append(paths, metadata.TypeName+"."+name)
				}
			case resourceschema.SetAttribute:
				if attribute.Sensitive && len(attribute.Validators) > 0 {
					paths = append(paths, metadata.TypeName+"."+name)
				}
			}
		}
	}

	want := []string{
		"mimecast_active_directory_integration.password_wo",
		"mimecast_dmarc_notification.emails",
		"mimecast_dmarc_user.user_email",
		"mimecast_google_workspace_directory_integration.service_account_key_wo",
		"mimecast_journaling_service.pop3_password_wo",
		"mimecast_journaling_service.smtp_password_wo",
		"provider.mimecast.proxy_url",
	}
	sort.Strings(paths)
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("sensitive validator inventory changed:\n got: %v\nwant: %v", paths, want)
	}
}

func TestSensitiveURLValidationDiagnosticsAreValueFree(t *testing.T) {
	ctx := context.Background()
	var schemaResponse frameworkprovider.SchemaResponse
	New("test")().Schema(ctx, frameworkprovider.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatal(schemaResponse.Diagnostics)
	}
	attribute, ok := schemaResponse.Schema.Attributes["proxy_url"].(providerschema.StringAttribute)
	if !ok || !attribute.Sensitive || len(attribute.Validators) == 0 {
		t.Fatalf("proxy_url must be sensitive and validated: %#v", attribute)
	}

	secret := "diagnostic-secret-marker"
	request := validator.StringRequest{
		ConfigValue: types.StringValue("https://proxy-user:" + secret + "@"),
		Path:        path.Root("proxy_url"),
	}
	var response validator.StringResponse
	for _, validate := range attribute.Validators {
		validate.ValidateString(ctx, request, &response)
	}
	if !response.Diagnostics.HasError() {
		t.Fatal("invalid proxy_url must produce an error")
	}
	assertDiagnosticsExclude(t, response.Diagnostics, secret)

	response = validator.StringResponse{}
	request.ConfigValue = types.StringValue("http://proxy.example.test:8080")
	for _, validate := range attribute.Validators {
		validate.ValidateString(ctx, request, &response)
	}
	if response.Diagnostics.HasError() {
		t.Fatalf("valid proxy_url diagnostics: %v", response.Diagnostics)
	}
}

func TestSensitiveEmailValidationDiagnosticsAreValueFree(t *testing.T) {
	ctx := context.Background()
	secret := "diagnostic-secret-marker"
	instance := NewDMARCUserResource()
	var schemaResponse resource.SchemaResponse
	instance.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatal(schemaResponse.Diagnostics)
	}
	attribute, ok := schemaResponse.Schema.Attributes["user_email"].(resourceschema.StringAttribute)
	if !ok || !attribute.Sensitive || len(attribute.Validators) == 0 {
		t.Fatalf("user_email must be sensitive and validated: %#v", attribute)
	}

	request := validator.StringRequest{
		ConfigValue: types.StringValue(strings.Repeat(secret, 24) + " not-an-email"),
		Path:        path.Root("user_email"),
	}
	var response validator.StringResponse
	for _, validate := range attribute.Validators {
		validate.ValidateString(ctx, request, &response)
	}
	if !response.Diagnostics.HasError() {
		t.Fatal("invalid sensitive email must produce an error")
	}
	assertDiagnosticsExclude(t, response.Diagnostics, secret)

	response = validator.StringResponse{}
	request.ConfigValue = types.StringValue("user@example.test")
	for _, validate := range attribute.Validators {
		validate.ValidateString(ctx, request, &response)
	}
	if response.Diagnostics.HasError() {
		t.Fatalf("valid sensitive email diagnostics: %v", response.Diagnostics)
	}
}

func TestSensitiveEmailSetValidationDiagnosticsAreValueFree(t *testing.T) {
	ctx := context.Background()
	secret := "diagnostic-secret-marker"
	instance := NewDMARCNotificationResource()
	var schemaResponse resource.SchemaResponse
	instance.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatal(schemaResponse.Diagnostics)
	}
	emails, ok := schemaResponse.Schema.Attributes["emails"].(resourceschema.SetAttribute)
	if !ok || !emails.Sensitive || len(emails.Validators) == 0 {
		t.Fatalf("emails must be sensitive and validated: %#v", emails)
	}
	request := validator.SetRequest{
		ConfigValue: types.SetValueMust(types.StringType, []attr.Value{types.StringValue(secret + " not-an-email")}),
		Path:        path.Root("emails"),
	}
	var setResponse validator.SetResponse
	for _, validate := range emails.Validators {
		validate.ValidateSet(ctx, request, &setResponse)
	}
	if !setResponse.Diagnostics.HasError() {
		t.Fatal("invalid sensitive email set must produce an error")
	}
	assertDiagnosticsExclude(t, setResponse.Diagnostics, secret)

	setResponse = validator.SetResponse{}
	request.ConfigValue = types.SetValueMust(types.StringType, []attr.Value{types.StringValue("user@example.test")})
	for _, validate := range emails.Validators {
		validate.ValidateSet(ctx, request, &setResponse)
	}
	if setResponse.Diagnostics.HasError() {
		t.Fatalf("valid sensitive email set diagnostics: %v", setResponse.Diagnostics)
	}
}

func assertDiagnosticsExclude(t *testing.T, diagnostics diag.Diagnostics, forbidden ...string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		text := diagnostic.Summary() + "\n" + diagnostic.Detail()
		if withPath, ok := diagnostic.(diag.DiagnosticWithPath); ok {
			text += "\n" + withPath.Path().String()
		}
		for _, value := range forbidden {
			if strings.Contains(text, value) {
				t.Fatalf("diagnostics exposed a sensitive value marker")
			}
		}
	}
}
