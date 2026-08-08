resource "mimecast_dmarc_spf_definition" "example" {
  domain_id     = mimecast_dmarc_delegated_domain.example.id
  version       = "v=spf1"
  all_qualifier = "~all"

  terms = [
    {
      type   = "include"
      target = "_spf.provider.example"
    }
  ]
}
