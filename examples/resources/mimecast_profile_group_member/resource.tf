resource "mimecast_profile_group_member" "alice" {
  group_id      = mimecast_profile_group.engineering.id
  email_address = "alice@example.com"
  note          = "Managed by Terraform"
}
