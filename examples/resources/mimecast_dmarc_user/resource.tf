resource "mimecast_dmarc_user" "example" {
  user_name       = "Terraform Example"
  user_email      = "dmarc-user@example.com"
  user_permission = "limited"
  reporting       = true
  timeline        = true
}
