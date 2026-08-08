resource "mimecast_dmarc_domain_group_association" "example" {
  group_id  = mimecast_dmarc_domain_group.example.id
  domain_id = mimecast_dmarc_managed_domain.example.id
}
