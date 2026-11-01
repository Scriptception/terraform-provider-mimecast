# Directory attribute type inventory

The `mimecast_attribute_types` data source implements `GET /directory/v1/attributeTypes`
from the [official Directory Management specification](https://developer.services.mimecast.com/portals/api/sites/mimecast-prod-apigee-developer/liveportal/apis/directory/spec),
reviewed on 2026-11-01. The application requires `Directories | Attributes | Read`.

The contract describes attribute definitions, including locally configured and
directory-linked definitions. This supports a typed read-only inventory; it does
not establish create/update/delete operations. The data source does not retrieve
addresses or address attribute values and does not modify the directory.

The response contains `attributeTypes` and cursor metadata in `meta.nextPage`.
Requests pass that cursor as `pageToken`. The provider's existing maximum page
size of 100 is below the endpoint limit of 1000. Omitting `origin` requests both
origins. No `includeCount` parameter is sent, avoiding its incompatibility with
`pageToken`.

Each item exposes the documented `id`, `description`, `prompt`, `promptGroup`,
`promptType`, `promptOrder`, `promptOptions`, and `allowedInViews` fields. Selection
options remain an unparsed string. Nullable numbers and booleans preserve omitted
values separately from zero and false. Results are sorted by ID. Missing or null
inventories, missing/duplicate IDs, repeated cursors, and HTTP failures return
errors; a failed later page cannot replace prior state with partial results.

Synthetic HTTP and Terraform state-mapping tests cover this contract. No tenant
API requests or live acceptance tests were performed. Public specification review
and synthetic tests do not establish live tenant compatibility.
