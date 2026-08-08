resource "mimecast_dns_authentication_outbound_definition" "example" {
  description = "tf-example-dkim"
  domain      = "example.com"
  selector    = "mimecast"
  sign_dkim   = true
  key_length  = 2048
}
