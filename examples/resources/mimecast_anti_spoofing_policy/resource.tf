resource "mimecast_anti_spoofing_policy" "example" {
  description = "tf-example-anti-spoofing"
  option      = "apply"
  from_part   = "both"
  from_type   = "external_addresses"
  to_type     = "internal_addresses"
  enabled     = true
}
