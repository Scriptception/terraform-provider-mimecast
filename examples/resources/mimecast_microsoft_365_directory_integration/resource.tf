resource "mimecast_microsoft_365_directory_integration" "example" {
  description                   = "tf-example-microsoft-365"
  domains                       = ["example.com"]
  tenant_domain                 = "example.onmicrosoft.com"
  server_subtype                = "standard"
  sync_guest_users              = false
  acknowledge_disabled_accounts = true
  enabled                       = true
  max_unlink                    = "100"
  sync_contacts                 = true
  delete_users                  = false
}
