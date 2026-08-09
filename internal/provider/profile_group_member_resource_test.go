package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func TestProfileGroupMemberImportAndReadPreservesIdentityBranch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		importID        string
		response        string
		wantEmail       string
		wantDomain      string
		wantName        string
		wantType        string
		wantNote        string
		wantInternal    bool
		wantEmailIsNull bool
		wantDomainNull  bool
		wantNoteNull    bool
	}{
		{
			name:            "email address",
			importID:        "group-1/Member@Example.invalid",
			response:        `{"groupMembers":[{"emailAddress":"member@example.invalid","domain":"example.invalid","name":"Email member","internal":true,"type":"created_manually","note":"remote note"}],"meta":{}}`,
			wantEmail:       "Member@Example.invalid",
			wantName:        "Email member",
			wantType:        "created_manually",
			wantNote:        "remote note",
			wantInternal:    true,
			wantDomainNull:  true,
			wantEmailIsNull: false,
		},
		{
			name:            "domain",
			importID:        "group-1/Example.invalid",
			response:        `{"groupMembers":[{"emailAddress":"example.invalid","domain":"example.invalid","name":"Domain member","internal":false,"type":"created_by_import","note":"remote note"}],"meta":{}}`,
			wantDomain:      "Example.invalid",
			wantName:        "Domain member",
			wantType:        "created_by_import",
			wantNote:        "remote note",
			wantInternal:    false,
			wantEmailIsNull: true,
			wantDomainNull:  false,
		},
		{
			name:            "empty note",
			importID:        "group-1/empty-note@example.invalid",
			response:        `{"groupMembers":[{"emailAddress":"empty-note@example.invalid","domain":"example.invalid","name":"Member without note","internal":true,"type":"created_manually","note":""}],"meta":{}}`,
			wantEmail:       "empty-note@example.invalid",
			wantName:        "Member without note",
			wantType:        "created_manually",
			wantInternal:    true,
			wantDomainNull:  true,
			wantEmailIsNull: false,
			wantNoteNull:    true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/oauth/token":
					_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
				case "/directory/cloud-gateway/v1/groups/group-1/members":
					_, _ = w.Write([]byte(test.response))
				default:
					http.NotFound(w, request)
				}
			}))
			defer server.Close()

			apiClient, err := client.New(client.Config{
				BaseURL:      server.URL,
				TokenURL:     server.URL + "/oauth/token",
				ClientID:     "id",
				ClientSecret: "secret",
				MaxRetries:   0,
			})
			if err != nil {
				t.Fatal(err)
			}
			instance := &profileGroupMemberResource{client: apiClient}
			var schemaResponse resource.SchemaResponse
			instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
			if schemaResponse.Diagnostics.HasError() {
				t.Fatalf("schema returned %d diagnostics", len(schemaResponse.Diagnostics))
			}
			state := tfsdk.State{
				Raw:    tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(context.Background()), nil),
				Schema: schemaResponse.Schema,
			}
			importResponse := resource.ImportStateResponse{State: state}
			instance.ImportState(context.Background(), resource.ImportStateRequest{ID: test.importID}, &importResponse)
			if len(importResponse.Diagnostics) != 0 {
				t.Fatalf("import returned %d diagnostics", len(importResponse.Diagnostics))
			}

			readResponse := resource.ReadResponse{State: importResponse.State}
			instance.Read(context.Background(), resource.ReadRequest{State: importResponse.State}, &readResponse)
			if len(readResponse.Diagnostics) != 0 {
				t.Fatalf("read returned %d diagnostics", len(readResponse.Diagnostics))
			}

			var got profileGroupMemberModel
			if diagnostics := readResponse.State.Get(context.Background(), &got); len(diagnostics) != 0 {
				t.Fatalf("state decode returned %d diagnostics", len(diagnostics))
			}
			if got.ID.ValueString() != test.importID {
				t.Fatal("refresh changed the imported composite ID")
			}
			if got.EmailAddress.IsNull() != test.wantEmailIsNull || got.EmailAddress.ValueString() != test.wantEmail {
				t.Fatal("refresh changed the email identity branch")
			}
			if got.Domain.IsNull() != test.wantDomainNull || got.Domain.ValueString() != test.wantDomain {
				t.Fatal("refresh changed the domain identity branch")
			}
			if got.Name.ValueString() != test.wantName || got.Type.ValueString() != test.wantType || got.Internal.ValueBool() != test.wantInternal {
				t.Fatal("refresh did not map computed member metadata")
			}
			if got.Note.IsNull() != test.wantNoteNull || got.Note.ValueString() != test.wantNote {
				t.Fatal("refresh did not map the member note")
			}
		})
	}
}
