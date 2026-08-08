variable "threat_reporting_client_state" {
  type      = string
  sensitive = true
}

resource "mimecast_threat_reporting_subscription" "example" {
  notification_url        = "https://webhook.example.com/mimecast"
  resource_type           = "threat-analysis"
  client_state_wo         = var.threat_reporting_client_state
  client_state_wo_version = 1
}
