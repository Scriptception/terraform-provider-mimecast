# Contributing

## Provider Scope

Manage durable Mimecast administration configuration with a complete API 2.0
create, read, update, delete, import, and drift lifecycle. Use typed Terraform
schemas and deterministic state. A data source is appropriate when Mimecast or
an external directory remains authoritative.

Do not model archive searches, event streams, queue or held-message actions,
message sending, file uploads, configuration restore, test actions, consent
flows, or threat remediation as resources.

## API Sources and Coverage

Use the current official Mimecast API 2.0 catalogue and operation contracts.
Do not commit upstream OpenAPI specifications, tenant responses, or response
fixtures containing real data.

Every unique method and path belongs in
[`capabilities/api-v2.json`](./capabilities/api-v2.json) with:

- API product, category, pagination style, and documented permission source.
- An implemented typed Terraform surface, contract status, and test status.
- Or a stable, specific lifecycle or API limitation and defer code.

Generic deferrals are rejected. Declarative operations with a complete safe
lifecycle but no implemented surface appear in
[`docs/api-gaps.md`](./docs/api-gaps.md) and block release.

```sh
make capability-check
make capability-refresh
make capability-doc
make capability-release-check
```

`capability-refresh` fetches current public specifications and marks new
operations unclassified. Review every change before committing it.

## Development

Use the Go version in `go.mod` and Terraform Plugin Framework protocol 6.

```sh
make fmt-check
make test
make vet
make vuln
make generate
make docs-check
```

Resources must:

- Fail before an HTTP request when provider `read_only` is true.
- Read after create and update instead of copying planned values to state.
- Implement import and remove state only for a confirmed not-found response.
- Preserve write-only secret handling and never persist request-only secrets.
- Use stable identity, deterministic ordering, and complete pagination.
- Avoid retrying non-idempotent writes unless the request is demonstrably safe.

Data sources must be side-effect free, typed, fully paginated, and
deterministically ordered.

## Acceptance Safety

Read-only acceptance tests use `TF_ACC=1` and the canonical environment
variables:

- `MIMECAST_ADDRESS`
- `MIMECAST_CLIENT_ID`
- `MIMECAST_SECRET`

Mutation acceptance is prohibited in a production tenant. It additionally
requires `MIMECAST_ACC_MUTATION=1` and
`MIMECAST_ACC_TENANT_DISPOSABLE=1`. All created names must start with
`tf-acc-mimecast-` and include a unique run identifier.

Use only empty test groups, disabled and narrowly targeted policies, and
reserved `.invalid` domains, URLs, and hosts. Tests must track every created ID,
delete in dependency order, and confirm absence after cleanup. Never mutate
tenant-wide controls, default policies, production routes, directory-synchronised
users, or existing objects to obtain test coverage.

## Sensitive Data

Never commit credentials, account codes, domains, identities, policy exports,
API response bodies, Terraform state, request logs, or test artefacts. Do not
log OAuth tokens, client secrets, SMTP passwords, service-account keys, or raw
request and response bodies.

## Pull Requests

Keep changes focused. Update examples, generated documentation, the capability
ledger, and the smallest tests that prove API contracts and Terraform lifecycle
behaviour. Ensure the working tree remains unchanged after `make docs-check`.

## Release Process

1. Set `VERSION` and add the matching changelog entry. The tag must be exactly
   `v$(cat VERSION)` and point to the tested main commit.
2. Confirm the repository is public and all branch protection and required
   checks are active.
3. Configure an RSA or DSA GPG signing key in `GPG_PRIVATE_KEY` and its
   passphrase in `PASSPHRASE`. Terraform Registry does not accept ECC provider
   signing keys.
4. Run `make release-check`. No entry may remain in `docs/api-gaps.md`.
5. Push the exact version tag. The release workflow reruns all gates, builds
   protocol 6 archives, signs the checksum, and publishes the manifest.
6. Complete Terraform Registry onboarding for `Scriptception/mimecast` and
   verify installation from the Registry before announcing the release.

Do not publish manually built or unsigned assets.
