# Changelog

## Unreleased

## 0.2.9 - 2026-08-10

- Preserved configured Address Alteration Set handles when Mimecast returns a
  different opaque secure ID during policy reads.
- Changed Address Alteration policy imports to use
  `policy_id,address_alteration_set_id`, so both opaque handles enter state.

## 0.2.8 - 2026-08-10

- Corrected unfiltered managed URL inventory reads to omit the filter object
  while retaining request-body token pagination.

## 0.2.7 - 2026-08-10

- Preserved the requested Address Alteration policy identity when Mimecast
  returns a different secure ID during filtered reads.
- Corrected Address Alteration policy inventory reads to omit the optional
  request body.

## 0.2.6 - 2026-08-09

- Prevented managed URLs whose decoded query parameter name is `access_token`
  from entering Terraform configuration or state. Resource validation,
  lifecycle reads, and import now fail with value-free diagnostics, while the
  managed URL data source excludes the whole record and reports the exclusion
  count.

## 0.2.5 - 2026-08-09

- Fixed ID-only imports for Address Alteration policies by hydrating the
  required policy scope during the first read.

## 0.2.4 - 2026-08-09

- Normalised delivery-route authentication-mechanism reads by trimming
  whitespace and discarding empty response placeholders.

## 0.2.3 - 2026-08-09

- Prevented sensitive proxy credentials and email addresses from appearing in
  validation diagnostics or set-element diagnostic paths.
- Rejected plaintext remote API and OAuth endpoints while retaining HTTP only
  for the exact numeric-loopback origins configured by local tests.

## 0.2.2 - 2026-08-09

- Reconstructed managed URL resource values from the documented decomposed API
  response while retaining incomplete entries in read-only inventory.

## 0.2.1 - 2026-08-09

- Normalised Cloud Gateway outbound IP discovery across both object-entry and
  string-array API 2.0 responses.
- Expanded typed account, gateway and user inventory with documented,
  non-sensitive API 2.0 fields.

## 0.2.0 - 2026-08-08

- Standardised on Mimecast API 2.0 and Terraform Plugin Framework protocol 6.
- Added fail-closed provider `read_only` mode, enabled by default.
- Added canonical `MIMECAST_ADDRESS`, `MIMECAST_CLIENT_ID`, and
  `MIMECAST_SECRET` environment variables with compatibility aliases.
- Replaced raw discovery output with typed, paginated, deterministically ordered
  data sources.
- Expanded the provider to 31 resources and 36 data sources, including DMARC
  Analyzer configuration and inventory, secret-safe directory integrations and
  journaling, address-alteration and Web Security policies, and threat-reporting
  subscriptions.
- Added write-only secret arguments and explicit version triggers for supported
  credential rotations without persisting credentials in Terraform state.
- Reworked resource read-back, import, drift, secret, retry, pagination, and
  API error handling.
- Classified all 371 unique operations in the current public Mimecast API
  catalogue: 152 map to typed Terraform surfaces, 219 have specific exclusions,
  and no declarative coverage gap remains. Added a live CI drift checker and
  release-blocking gap report.
- Added synthetic contract and lifecycle validation, mutation safety gates,
  generated documentation checks, vulnerability scanning, and pinned release
  tooling.
- Added signed GoReleaser assets and Terraform Registry protocol 6 metadata.

## 0.1.1

- Hardened API handling for legacy Mimecast `fail` envelopes returned with HTTP
  200 responses.
- Added one-time OAuth token refresh on 401 responses.
- Allowed `max_retries = 0` to disable transient retry attempts.
- Marked create/delete-only resources with replacement semantics.

## 0.1.0

- Added the initial API 2.0 provider implementation and CI scaffolding.
