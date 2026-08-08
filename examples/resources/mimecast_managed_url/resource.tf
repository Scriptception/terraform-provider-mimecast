resource "mimecast_managed_url" "blocked_domain" {
  url        = "malicious.example"
  action     = "block"
  match_type = "domain"
  comment    = "Managed by Terraform"
}
