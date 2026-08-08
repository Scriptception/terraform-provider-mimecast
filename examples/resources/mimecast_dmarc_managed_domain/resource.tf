resource "mimecast_dmarc_managed_domain" "example" {
  domain          = "example.com"
  activity_status = "active"
}
