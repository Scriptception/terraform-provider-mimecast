resource "mimecast_dmarc_definition" "example" {
  domain_id        = mimecast_dmarc_delegated_domain.example.id
  policy_preset_id = mimecast_dmarc_policy_preset.example.id
}
