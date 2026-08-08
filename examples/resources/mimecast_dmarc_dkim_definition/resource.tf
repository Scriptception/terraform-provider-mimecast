resource "mimecast_dmarc_dkim_definition" "example" {
  domain_id   = mimecast_dmarc_delegated_domain.example.id
  selector    = "selector1"
  record_type = "cname"
  hostname    = "selector1._domainkey.provider.example"
}
