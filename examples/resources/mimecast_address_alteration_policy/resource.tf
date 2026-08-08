resource "mimecast_address_alteration_policy" "example" {
  address_alteration_set_id = "address-alteration-set-id"

  policy = {
    description   = "tf-example-address-alteration"
    enabled       = true
    enforced      = true
    override      = false
    bidirectional = false
    from_part     = "both"
    from_eternal  = true
    to_eternal    = true
    from = {
      type = "external_addresses"
    }
    to = {
      type = "internal_addresses"
    }
  }
}
