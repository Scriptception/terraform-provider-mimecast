resource "mimecast_address_alteration_definition" "example" {
  folder_id        = "address-alteration-set-id"
  address_type     = "envelope_to"
  original_address = "old-address@example.com"
  new_address      = "new-address@example.com"
  routing          = "inbound"
}
