resource "mimecast_dns_authentication_outbound_policy" "example" {
  description   = "tf-example-dkim-policy"
  definition_id = mimecast_dns_authentication_outbound_definition.example.id
  from_part     = "both"
  from_type     = "internal_addresses"
  to_type       = "external_addresses"
  enabled       = true
}
