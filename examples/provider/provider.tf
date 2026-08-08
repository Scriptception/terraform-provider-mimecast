terraform {
  required_version = ">= 1.11.0"

  required_providers {
    mimecast = {
      source  = "Scriptception/mimecast"
      version = "~> 0.2"
    }
  }
}

provider "mimecast" {
  # Credentials use the canonical environment variables:
  # MIMECAST_ADDRESS
  # MIMECAST_CLIENT_ID
  # MIMECAST_SECRET
  read_only = true
}
