resource "mimecast_dmarc_delegated_domain" "example" {
  managed_domain_id = mimecast_dmarc_managed_domain.example.id
}
