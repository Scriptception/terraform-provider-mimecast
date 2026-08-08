resource "mimecast_journaling_service" "example" {
  description                        = "tf-example-journaling"
  enabled                            = true
  message_format                     = "standard_eml"
  remove_journal_headers             = true
  journal_non_internal_addresses     = true
  journal_unknown_internal_addresses = true
  transfer_protocol                  = "smtp"
  smtp_email_address                 = "journal@example.com"
  smtp_ip_ranges                     = ["192.0.2.0/24"]
  smtp_uses_authentication           = false
  smtp_uses_tls                      = true
  smtp_extended_deduplication        = true
  smtp_inactivity_timeout            = 180
}
