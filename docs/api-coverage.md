# Mimecast API 2.0 Capability Coverage

Checked against the [official Mimecast API catalogue](https://developer.services.mimecast.com/portals/api/sites/mimecast-prod-apigee-developer/liveportal/apis) on 2026-08-08. The catalogue contains **19 products**, **475 product operation entries**, and **371 unique method and path operations**. Product entries are higher because 104 operations appear in more than one product.

Every operation is classified in [`capabilities/api-v2.json`](../capabilities/api-v2.json): **152 have an implemented typed Terraform surface**, **219 are excluded**, and **0 declarative gaps block release**.

## Coverage Definition

Coverage means every current API operation is tied to a typed resource or data source, or has a stable, specific lifecycle or API limitation. Console-only settings remain outside coverage until Mimecast publishes an API contract. Excluding an operation with a documented complete and safe Terraform lifecycle creates a release-blocking gap; the checker does not accept a generic deferral.

The live checker fails on new, removed, moved, unknown, or unclassified operations. It also validates product, permission, pagination, contract, test status, and generated surface documentation. Upstream specifications are never committed.

## Product Summary

| API product | Terraform | Excluded | Blocking gaps | Total entries |
| --- | ---: | ---: | ---: | ---: |
| Account Management (`accountmanagement`) | 4 | 8 | 0 | 12 |
| Data Retention (`archivedataaccess`) | 0 | 10 | 0 | 10 |
| Audit Events (`auditevents`) | 0 | 7 | 0 | 7 |
| Awareness Training (`awarenesstraining`) | 0 | 10 | 0 | 10 |
| Email Security (`cloud-integrated`) | 5 | 2 | 0 | 7 |
| Email Security Cloud Gateway (`cloudgateway`) | 9 | 19 | 0 | 28 |
| Connectors (`connector`) | 2 | 3 | 0 | 5 |
| DMARC Analyzer (`dmarcanalyzer`) | 45 | 40 | 0 | 85 |
| Domain Management (`domainmanagement`) | 6 | 17 | 0 | 23 |
| Email Security Onboarding (`emailsecurityonboarding`) | 72 | 33 | 0 | 105 |
| Human Risk (`human-risk`) | 0 | 7 | 0 | 7 |
| Integration Management (`integrationmanagement`) | 0 | 8 | 0 | 8 |
| Policy Management (`policymanagement`) | 55 | 9 | 0 | 64 |
| Security Events (`securityevents`) | 0 | 4 | 0 | 4 |
| Threat Management (`threatmanagement`) | 0 | 10 | 0 | 10 |
| Threat Remediation (`threatremediationci`) | 0 | 4 | 0 | 4 |
| Threats, Security Events, and Data (`threatssecurityeventsanddataforcg`) | 4 | 17 | 0 | 21 |
| Threats, Security Events, and Data (`threatssecurityeventsanddataforci`) | 0 | 2 | 0 | 2 |
| User and Group Management (`userandgroupmanagement`) | 21 | 42 | 0 | 63 |

Counts include cross-listed operations in every applicable product.

## Terraform Surfaces

| Surface | Operations |
| --- | ---: |
| `data_source.mimecast_account` | 1 |
| `data_source.mimecast_account_packages` | 1 |
| `data_source.mimecast_address_alteration_definitions` | 1 |
| `data_source.mimecast_address_alteration_policies` | 1 |
| `data_source.mimecast_address_alteration_sets` | 1 |
| `data_source.mimecast_anti_spoofing_bypass_policies` | 1 |
| `data_source.mimecast_anti_spoofing_policies` | 1 |
| `data_source.mimecast_blocked_sender_policies` | 1 |
| `data_source.mimecast_cloud_integrated_default_policy` | 1 |
| `data_source.mimecast_connectors` | 2 |
| `data_source.mimecast_delivery_route_definitions` | 1 |
| `data_source.mimecast_delivery_route_policies` | 1 |
| `data_source.mimecast_dmarc_delegated_domains` | 1 |
| `data_source.mimecast_dmarc_domain_groups` | 2 |
| `data_source.mimecast_dmarc_domains` | 2 |
| `data_source.mimecast_dmarc_notifications` | 2 |
| `data_source.mimecast_dmarc_policy_presets` | 1 |
| `data_source.mimecast_dmarc_users` | 1 |
| `data_source.mimecast_dmarc_vendors` | 2 |
| `data_source.mimecast_dns_authentication_outbound_definitions` | 1 |
| `data_source.mimecast_dns_authentication_outbound_policies` | 1 |
| `data_source.mimecast_emergency_contact` | 1 |
| `data_source.mimecast_external_domains` | 2 |
| `data_source.mimecast_gateway_details` | 1 |
| `data_source.mimecast_greylisting_policies` | 1 |
| `data_source.mimecast_internal_domains` | 2 |
| `data_source.mimecast_journaling_services` | 2 |
| `data_source.mimecast_managed_urls` | 1 |
| `data_source.mimecast_outbound_ip_addresses` | 1 |
| `data_source.mimecast_pending_domains` | 2 |
| `data_source.mimecast_profile_group_members` | 1 |
| `data_source.mimecast_profile_groups` | 1 |
| `data_source.mimecast_roles` | 1 |
| `data_source.mimecast_threat_reporting_subscriptions` | 1 |
| `data_source.mimecast_users` | 1 |
| `data_source.mimecast_whoami` | 1 |
| `resource.mimecast_active_directory_integration` | 4 |
| `resource.mimecast_address_alteration_definition` | 3 |
| `resource.mimecast_address_alteration_policy` | 4 |
| `resource.mimecast_anti_spoofing_bypass_policy` | 4 |
| `resource.mimecast_anti_spoofing_policy` | 4 |
| `resource.mimecast_blocked_sender_policy` | 4 |
| `resource.mimecast_cloud_integrated_policy` | 4 |
| `resource.mimecast_delivery_route_definition` | 4 |
| `resource.mimecast_delivery_route_policy` | 4 |
| `resource.mimecast_dmarc_definition` | 3 |
| `resource.mimecast_dmarc_delegated_domain` | 3 |
| `resource.mimecast_dmarc_dkim_definition` | 7 |
| `resource.mimecast_dmarc_domain_group` | 4 |
| `resource.mimecast_dmarc_domain_group_association` | 3 |
| `resource.mimecast_dmarc_managed_domain` | 4 |
| `resource.mimecast_dmarc_notification` | 4 |
| `resource.mimecast_dmarc_policy_preset` | 4 |
| `resource.mimecast_dmarc_spf_definition` | 4 |
| `resource.mimecast_dmarc_user` | 4 |
| `resource.mimecast_dns_authentication_outbound_definition` | 4 |
| `resource.mimecast_dns_authentication_outbound_policy` | 4 |
| `resource.mimecast_google_workspace_directory_integration` | 4 |
| `resource.mimecast_greylisting_policy` | 4 |
| `resource.mimecast_journaling_service` | 4 |
| `resource.mimecast_managed_url` | 2 |
| `resource.mimecast_microsoft_365_directory_integration` | 4 |
| `resource.mimecast_outbound_ip_addresses` | 3 |
| `resource.mimecast_profile_group` | 4 |
| `resource.mimecast_profile_group_member` | 3 |
| `resource.mimecast_threat_reporting_subscription` | 4 |
| `resource.mimecast_web_security_url_policy` | 4 |

## Stable Deferrals

| Defer code | Operations |
| --- | ---: |
| `account_operational_metadata` | 3 |
| `analytical_result_data` | 17 |
| `archive_data_workflow` | 13 |
| `external_directory_authority` | 24 |
| `imperative_verification_action` | 24 |
| `interactive_connector_consent` | 3 |
| `interactive_integration_consent` | 8 |
| `legacy_policy_superseded` | 6 |
| `message_operations_workflow` | 12 |
| `no_safe_delete_contract` | 7 |
| `no_safe_read_contract` | 2 |
| `operation_has_no_durable_state` | 23 |
| `operational_recovery_action` | 4 |
| `operational_service_data` | 22 |
| `secret_not_readable_or_state_safe` | 3 |
| `security_telemetry_stream` | 12 |
| `threat_operations_workflow` | 29 |
| `transient_domain_verification` | 4 |
| `workflow_not_desired_state` | 3 |

## Maintenance

```sh
make capability-check
make capability-doc
make capability-refresh
make capability-release-check
```

A refresh marks new operations unclassified. Release checking also fails while [`docs/api-gaps.md`](./api-gaps.md) contains any operation.
