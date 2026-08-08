resource "mimecast_profile_group" "engineering" {
  description = "tf-example-engineering"
}

resource "mimecast_greylisting_policy" "engineering" {
  description   = "tf-example-engineering-greylisting"
  option        = "apply"
  from_type     = "profile_group"
  from_group_id = mimecast_profile_group.engineering.id
  to_type       = "external_addresses"
  enabled       = true
}

resource "mimecast_managed_url" "blocked_domain" {
  url        = "malicious.example"
  action     = "block"
  match_type = "domain"
  comment    = "Managed by Terraform"
}
