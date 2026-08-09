# Terraform Provider for Mimecast

[![Tests](https://github.com/Scriptception/terraform-provider-mimecast/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/Scriptception/terraform-provider-mimecast/actions/workflows/test.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](./LICENSE)

Manage durable Mimecast administration configuration with Terraform.

This is an unofficial provider. It is not affiliated with, maintained by,
sponsored by, or endorsed by Mimecast.

## Scope

The provider uses Mimecast API 2.0 OAuth and Terraform Plugin Framework
protocol 6. Its 31 typed resources cover supported Cloud Gateway policies and
definitions, managed URLs, profile groups and members, outbound IP addresses,
Cloud Integrated policies, DMARC Analyzer configuration, address alteration,
Web Security URL policies, directory integrations, journaling services, and
threat-reporting subscriptions. Its 36 typed data sources expose account,
domain, user, role, connector, journaling, policy, DMARC, integration, and
subscription inventory without placing raw API responses in state.

[`docs/api-coverage.md`](./docs/api-coverage.md) summarises all 371 unique
operations in the current public API catalogue. The checked operation ledger is
[`capabilities/api-v2.json`](./capabilities/api-v2.json). Declarative operations
with a complete safe lifecycle but no implemented typed surface are listed in
[`docs/api-gaps.md`](./docs/api-gaps.md) and block a release.

## Requirements

- Terraform 1.11 or later.
- A Mimecast API 2.0 application using OAuth 2.0 client credentials.
- The API products and role permissions required by the objects being read or
  managed.
- Go 1.25.12 when building from source.

API product choices for a Mimecast Integrations Hub application cannot be
changed after creation. Confirm the required products before creating a
dedicated application.

## Authentication

Set the canonical environment variables without committing their values:

```sh
export MIMECAST_ADDRESS="https://api.services.mimecast.com"
export MIMECAST_CLIENT_ID="..."
export MIMECAST_SECRET="..."
```

`MIMECAST_BASE_URL` is accepted as an alias for `MIMECAST_ADDRESS` and
`MIMECAST_CLIENT_SECRET` is accepted as an alias for `MIMECAST_SECRET`.
Canonical variables take precedence.

```hcl
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
  read_only = true
}
```

Other provider settings can be supplied in configuration or through
`MIMECAST_TOKEN_URL`, `MIMECAST_TOKEN_AUTH_METHOD`, `MIMECAST_SCOPES`,
`MIMECAST_TIMEOUT_SECONDS`, `MIMECAST_MAX_RETRIES`, `MIMECAST_PAGE_SIZE`,
`MIMECAST_READ_ONLY`, `MIMECAST_PROXY_URL`, and `MIMECAST_INSECURE`.

## Read-Only Safety

`read_only` defaults to `true`. In this mode, data sources, refresh, plan, and
import can call read operations, while every create, update, and delete fails
before an API request is sent.

Set `read_only = false` only when the configuration is intended to manage the
target tenant. Review a saved plan before applying. Directory-synchronised
Cloud Gateway users and discovery-only connector and pending-domain objects are
not mutable provider resources.

## Example

```hcl
resource "mimecast_profile_group" "engineering" {
  description = "tf-example-engineering"
}

resource "mimecast_greylisting_policy" "engineering" {
  description   = "tf-example-engineering-greylisting"
  option        = "apply"
  from_type     = "profile_group"
  from_group_id = mimecast_profile_group.engineering.id
  to_type       = "external_addresses"
  enabled       = true
}
```

## Limitations

- API 1.0 request signing is not supported. The provider requires an API 2.0
  OAuth application; a small number of current policy contracts retain
  compatibility-style `/api/policy` paths in the official catalogue.
- Administration Console features without a public API 2.0 lifecycle cannot be
  represented.
- An authenticated `403` indicates that the API application lacks a required
  product or role permission. The provider does not bypass that boundary.
- Connector consent, domain verification, directory synchronisation tests,
  message operations, searches, telemetry, remediation, and snapshot restore
  are workflows rather than Terraform-managed objects.
- Directory integration, journaling, and threat-subscription secrets are
  write-only arguments and never enter Terraform state. Existing objects can be
  imported without those secrets; supply a new value and its version trigger
  only when intentionally rotating it.
- Managed URLs whose decoded query parameter name is `access_token` are not a
  supported Terraform surface. The resource refuses configuration, refresh,
  and import with value-free diagnostics. The `mimecast_managed_urls` data
  source excludes each entire affected record before state mapping and reports
  the number in `excluded_access_token_count`; it does not delete or change the
  remote record.
- State, plans, and backend backups created with provider versions before 0.2.6
  may still contain managed URL credential values. Remove affected records from
  state and retained artefacts according to the backend's procedures, then
  rotate the exposed credential. Upgrading the provider cannot purge historical
  state or rotate a remote credential.
- Mimecast can return a different opaque secure ID for the same Address
  Alteration policy or set on later reads. Import Address Alteration policies
  with `policy_id,address_alteration_set_id`; the provider retains those working
  handles in state and uses fresh reads only for the policy configuration.
- DMARC vendor associations have no published read contract. Vendor record
  updates and address-alteration set creation lack a complete provider-owned
  lifecycle, so those four mutation operations remain explicitly excluded.

## Development

```sh
make fmt-check
make test
make vet
make vuln
make capability-check
make docs-check
```

Live read-only acceptance tests require the canonical Mimecast environment
variables. Mutation acceptance is separately gated and may run only in a
disposable tenant. Every test object must start with `tf-acc-mimecast-`; see
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Publishing

Release assets and checksums are produced by GoReleaser and signed with a GPG
key. Repository maintainers must configure the signing secrets and publish the
exact tag matching `VERSION` after all release gates pass. The release workflow
signs the checksum file. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md#release-process).

## License

[Mozilla Public License 2.0](./LICENSE).
