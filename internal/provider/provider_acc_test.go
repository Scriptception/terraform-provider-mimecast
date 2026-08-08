package provider

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"mimecast": providerserver.NewProtocol6WithError(New("test")()),
}

func TestAccWhoamiDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		ErrorCheck:               testAccPermissionErrorCheck(t),
		Steps: []resource.TestStep{
			{
				Config: `
provider "mimecast" {}

data "mimecast_whoami" "current" {}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.mimecast_whoami.current", "id", "whoami"),
					resource.TestCheckResourceAttrSet("data.mimecast_whoami.current", "type"),
				),
			},
		},
	})
}

func testAccPermissionErrorCheck(t *testing.T) resource.ErrorCheckFunc {
	t.Helper()
	return func(err error) error {
		if err == nil {
			return nil
		}
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "returned 403") || strings.Contains(message, "access denied") || strings.Contains(message, "forbidden") {
			t.Skip("Mimecast API application is not permitted to read this acceptance-test surface")
		}
		return err
	}
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("MIMECAST_CLIENT_ID") == "" {
		t.Skip("MIMECAST_CLIENT_ID must be set for acceptance tests")
	}
	if os.Getenv("MIMECAST_SECRET") == "" && os.Getenv("MIMECAST_CLIENT_SECRET") == "" {
		t.Skip("MIMECAST_SECRET or MIMECAST_CLIENT_SECRET must be set for acceptance tests")
	}
}
