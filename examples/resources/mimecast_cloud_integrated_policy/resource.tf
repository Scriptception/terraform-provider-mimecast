resource "mimecast_cloud_integrated_policy" "example" {
  name            = "tf-example-email-security"
  description     = "Managed by Terraform"
  protection_mode = "MONITOR_ONLY"

  targets = {
    senders = {
      route = "ALL"
    }
    recipients = {
      route = "ALL"
    }
    address_match = "BOTH"
  }

  actions = {
    malware       = "QUARANTINE"
    phishing      = "QUARANTINE"
    untrustworthy = "MOVE_TO_JUNK"
    spam          = "MOVE_TO_JUNK"
  }

  alerts = {
    malware       = true
    phishing      = true
    untrustworthy = false
    spam          = false
  }

  security_engines = {
    url_click = {
      sensitivity             = "MEDIUM"
      scan_urls_in_attachment = true
      rewrite_enabled         = true
      rewrite_mode            = "MODERATE"
      user_identification     = "BASIC"
    }
    phishing = {
      sensitivity_phishing_high      = 5
      sensitivity_untrustworthy_high = 5
      scan_outbound_emails           = true
    }
    impersonation = {
      code_breaker_status = "ENABLED"
      reporting_status    = "ENABLED"
      silencer_status     = "LEARNING"
    }
    attachments = {
      sandbox_enabled     = true
      unreadable_archives = "QUARANTINE"
    }
  }
}
