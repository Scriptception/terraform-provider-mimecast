resource "mimecast_delivery_route_policy" "primary" {
  description   = "tf-example-primary-delivery"
  definition_id = mimecast_delivery_route_definition.primary.id
  from_part     = "both"

  from_type = "internal_addresses"
  to_type   = "external_addresses"
  enabled   = true
}
