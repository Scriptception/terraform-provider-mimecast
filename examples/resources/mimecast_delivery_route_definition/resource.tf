resource "mimecast_delivery_route_definition" "primary" {
  description = "tf-example-primary-route"
  hostname    = "mail.example.com"
  port        = 25
}
