variable "google_service_account_key" {
  type      = string
  sensitive = true
}

resource "mimecast_google_workspace_directory_integration" "example" {
  description                    = "tf-example-google-workspace"
  domains                        = ["example.com"]
  user                           = "directory-admin@example.com"
  service_account_key_wo         = var.google_service_account_key
  service_account_key_wo_version = 1
  acknowledge_disabled_accounts  = true
  enabled                        = true
  max_unlink                     = "100"
  delete_users                   = false
}
