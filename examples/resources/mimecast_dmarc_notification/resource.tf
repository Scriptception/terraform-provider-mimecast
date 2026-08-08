resource "mimecast_dmarc_notification" "example" {
  type      = "dmarcSummary"
  emails    = ["dmarc-alerts@example.com"]
  frequency = "daily"
}
