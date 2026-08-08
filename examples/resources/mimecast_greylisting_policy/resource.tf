resource "mimecast_greylisting_policy" "engineering" {
  description = "tf-example-engineering-greylisting"
  option      = "apply"

  from_type     = "profile_group"
  from_group_id = mimecast_profile_group.engineering.id

  to_type = "external_addresses"
  enabled = true
}
