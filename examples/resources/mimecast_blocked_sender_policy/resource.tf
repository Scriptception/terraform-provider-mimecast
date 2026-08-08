resource "mimecast_blocked_sender_policy" "example" {
  description        = "tf-example-blocked-sender"
  option             = "block_sender"
  from_part          = "both"
  from_type          = "individual_email_address"
  from_email_address = "sender@example.invalid"
  to_type            = "internal_addresses"
  enabled            = true
}
