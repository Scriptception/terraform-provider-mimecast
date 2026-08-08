resource "mimecast_anti_spoofing_bypass_policy" "example" {
  description = "tf-example-anti-spoofing-bypass"
  option      = "enable_bypass"
  from_type   = "email_domain"
  from_domain = "partner.example"
  to_type     = "internal_addresses"
  spf_domains = ["partner.example"]
  enabled     = true
}
