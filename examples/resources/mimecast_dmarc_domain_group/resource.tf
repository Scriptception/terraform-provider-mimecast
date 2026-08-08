resource "mimecast_dmarc_domain_group" "example" {
  name                             = "tf-example-domains"
  type                             = "static"
  does_auto_include_org_subdomains = false
  included_domain_ids              = [mimecast_dmarc_managed_domain.example.id]
}
