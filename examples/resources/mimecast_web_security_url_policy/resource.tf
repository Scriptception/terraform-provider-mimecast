# Mimecast does not expose a list endpoint for this policy family. Use the
# import command with a policy ID from the Administration Console to seed state.
resource "mimecast_web_security_url_policy" "example" {
  description = "tf-example-web-security"

  targets = [
    {
      policy = {
        description   = "tf-example-web-security-target"
        enabled       = true
        enforced      = true
        override      = false
        bidirectional = false
        from_eternal  = true
        to_eternal    = true
        from = {
          type = "everyone"
        }
        to = {
          type = "everyone"
        }
      }
    }
  ]

  url_actions = [
    {
      action = "block"
      type   = "domain"
      value  = "blocked.example"
    }
  ]
}
