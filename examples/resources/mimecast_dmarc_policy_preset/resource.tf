resource "mimecast_dmarc_policy_preset" "example" {
  name             = "tf-example-policy"
  description      = "Managed by Terraform"
  version          = "DMARC1"
  policy           = "none"
  subdomain_policy = "none"
  dkim_alignment   = "r"
  spf_alignment    = "r"
  percentage       = 100
}
