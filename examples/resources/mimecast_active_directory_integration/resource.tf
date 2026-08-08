variable "active_directory_password" {
  type      = string
  sensitive = true
}

resource "mimecast_active_directory_integration" "example" {
  description                   = "tf-example-active-directory"
  domains                       = ["example.com"]
  hostname                      = "ad1.example.com"
  alternate_hostname            = "ad2.example.com"
  port                          = 636
  user_dn                       = "CN=mimecast,OU=Service Accounts,DC=example,DC=com"
  password_wo                   = var.active_directory_password
  password_wo_version           = 1
  root_dn                       = "DC=example,DC=com"
  encryption_mode               = "strict"
  acknowledge_disabled_accounts = true
  enabled                       = true
  max_unlink                    = "100"
  sync_contacts                 = true
  delete_users                  = false
}
