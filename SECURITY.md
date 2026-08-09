# Security Policy

## Supported Versions

Security fixes are provided for the latest published minor release.

## Reporting a Vulnerability

Use a private [GitHub security advisory](https://github.com/Scriptception/terraform-provider-mimecast/security/advisories/new).
Do not open a public issue containing credentials, tenant identifiers, user
data, policy exports, API responses, Terraform state, or debug logs.

Include the affected provider version, impact, minimal reproduction steps, and
redacted configuration. Do not attach real state or tenant responses.

## Security Boundaries

- Provider `read_only` defaults to true and blocks writes before a request.
- OAuth and resource secrets are sensitive; request-only secrets use write-only
  arguments where a safe lifecycle exists.
- API errors and diagnostics must not include credentials, authentication
  headers, request bodies, or unbounded response content.
- Managed URL records whose decoded query parameter name is `access_token` are
  refused by resource configuration, read, and import paths with value-free
  diagnostics. The managed URL data source excludes the whole record before
  state mapping and reports only an exclusion count.
- `insecure = true` disables TLS certificate verification and must not be used
  outside isolated testing.
- Terraform state can contain identifiers and managed configuration. Protect it
  with an encrypted backend and least-privilege access.

The provider cannot compensate for an over-privileged Mimecast application or
an unprotected Terraform state backend.
