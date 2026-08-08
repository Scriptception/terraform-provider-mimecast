package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type dmarcDNSRecordDataSourceModel struct {
	Domain   types.String `tfsdk:"domain"`
	Value    types.String `tfsdk:"value"`
	Selector types.String `tfsdk:"selector"`
}

func dmarcDNSRecordDataSourceAttribute(description string) dsschema.ListNestedAttribute {
	return dsschema.ListNestedAttribute{
		Description: description,
		Computed:    true,
		NestedObject: dsschema.NestedAttributeObject{Attributes: map[string]dsschema.Attribute{
			"domain":   dsString("DNS record owner name."),
			"value":    dsString("DNS record value."),
			"selector": dsString("DKIM selector when applicable."),
		}},
	}
}

func dmarcDNSRecordDataSourceModels(records []client.DMARCDNSRecordValue) []dmarcDNSRecordDataSourceModel {
	if records == nil {
		return nil
	}
	items := make([]dmarcDNSRecordDataSourceModel, 0, len(records))
	for _, record := range records {
		items = append(items, dmarcDNSRecordDataSourceModel{
			Domain: stringValue(record.Domain), Value: stringValue(record.Value), Selector: stringValue(record.Selector),
		})
	}
	return items
}

type dmarcManagedDomainDataSourceItemModel struct {
	ID                types.String                    `tfsdk:"id"`
	Domain            types.String                    `tfsdk:"domain"`
	ActivityStatus    types.String                    `tfsdk:"activity_status"`
	DetectedStatus    types.String                    `tfsdk:"detected_status"`
	Status            types.String                    `tfsdk:"status"`
	DMARCPolicy       types.String                    `tfsdk:"dmarc_policy"`
	DMARCStatus       types.String                    `tfsdk:"dmarc_status"`
	DMARCDelegationID types.String                    `tfsdk:"dmarc_delegation_id"`
	DKIMStatus        types.String                    `tfsdk:"dkim_status"`
	DKIMDelegationID  types.String                    `tfsdk:"dkim_delegation_id"`
	SPFStatus         types.String                    `tfsdk:"spf_status"`
	SPFDelegationID   types.String                    `tfsdk:"spf_delegation_id"`
	IsPolicyInherited types.Bool                      `tfsdk:"is_policy_inherited"`
	DNSA              []dmarcDNSRecordDataSourceModel `tfsdk:"dns_a_records"`
	DNSAAAA           []dmarcDNSRecordDataSourceModel `tfsdk:"dns_aaaa_records"`
	DNSCNAME          []dmarcDNSRecordDataSourceModel `tfsdk:"dns_cname_records"`
	DNSMX             []dmarcDNSRecordDataSourceModel `tfsdk:"dns_mx_records"`
	DNSNS             []dmarcDNSRecordDataSourceModel `tfsdk:"dns_ns_records"`
	DNSTXT            []dmarcDNSRecordDataSourceModel `tfsdk:"dns_txt_records"`
	DNSPTR            []dmarcDNSRecordDataSourceModel `tfsdk:"dns_ptr_records"`
	DNSSRV            []dmarcDNSRecordDataSourceModel `tfsdk:"dns_srv_records"`
	DNSSOA            []dmarcDNSRecordDataSourceModel `tfsdk:"dns_soa_records"`
	DNSCAA            []dmarcDNSRecordDataSourceModel `tfsdk:"dns_caa_records"`
	DNSDS             []dmarcDNSRecordDataSourceModel `tfsdk:"dns_ds_records"`
	DNSDNSKEY         []dmarcDNSRecordDataSourceModel `tfsdk:"dns_dnskey_records"`
	DNSDMARC          []dmarcDNSRecordDataSourceModel `tfsdk:"dns_dmarc_records"`
	DNSDKIM           []dmarcDNSRecordDataSourceModel `tfsdk:"dns_dkim_records"`
}

type dmarcManagedDomainsDataSourceModel struct {
	ID    types.String                            `tfsdk:"id"`
	Items []dmarcManagedDomainDataSourceItemModel `tfsdk:"items"`
}

func dmarcManagedDomainDataSourceAttributes() map[string]dsschema.Attribute {
	return map[string]dsschema.Attribute{
		"id": dsID("DMARC Analyzer managed-domain ID."), "domain": dsString("Managed domain name."),
		"activity_status": dsString("Managed-domain activity status."), "detected_status": dsString("Detected-domain activity status."),
		"status": dsString("Managed-domain lifecycle stage."), "dmarc_policy": dsString("Published DMARC policy."),
		"dmarc_status": dsString("DMARC DNS configuration status."), "dmarc_delegation_id": dsID("DMARC delegation record ID."),
		"dkim_status": dsString("DKIM DNS configuration status."), "dkim_delegation_id": dsID("DKIM delegation record ID."),
		"spf_status": dsString("SPF DNS configuration status."), "spf_delegation_id": dsID("SPF delegation record ID."),
		"is_policy_inherited": dsBool("Whether the DMARC policy is inherited from a parent domain."),
		"dns_a_records":       dmarcDNSRecordDataSourceAttribute("A records returned for the domain."),
		"dns_aaaa_records":    dmarcDNSRecordDataSourceAttribute("AAAA records returned for the domain."),
		"dns_cname_records":   dmarcDNSRecordDataSourceAttribute("CNAME records returned for the domain."),
		"dns_mx_records":      dmarcDNSRecordDataSourceAttribute("MX records returned for the domain."),
		"dns_ns_records":      dmarcDNSRecordDataSourceAttribute("NS records returned for the domain."),
		"dns_txt_records":     dmarcDNSRecordDataSourceAttribute("TXT records returned for the domain."),
		"dns_ptr_records":     dmarcDNSRecordDataSourceAttribute("PTR records returned for the domain."),
		"dns_srv_records":     dmarcDNSRecordDataSourceAttribute("SRV records returned for the domain."),
		"dns_soa_records":     dmarcDNSRecordDataSourceAttribute("SOA records returned for the domain."),
		"dns_caa_records":     dmarcDNSRecordDataSourceAttribute("CAA records returned for the domain."),
		"dns_ds_records":      dmarcDNSRecordDataSourceAttribute("DS records returned for the domain."),
		"dns_dnskey_records":  dmarcDNSRecordDataSourceAttribute("DNSKEY records returned for the domain."),
		"dns_dmarc_records":   dmarcDNSRecordDataSourceAttribute("DMARC records returned for the domain."),
		"dns_dkim_records":    dmarcDNSRecordDataSourceAttribute("DKIM records returned for the domain."),
	}
}

func dmarcManagedDomainDataSourceItem(domain client.ManagedDMARCDomain) dmarcManagedDomainDataSourceItemModel {
	model := dmarcManagedDomainDataSourceItemModel{
		ID: stringValue(domain.ID), Domain: stringValue(domain.Domain), ActivityStatus: stringValue(domain.ActivityStatus),
		DetectedStatus: stringValue(domain.DetectedStatus), Status: stringValue(domain.Status), DMARCPolicy: stringValue(domain.DMARCPolicy),
		DMARCStatus: stringValue(domain.DMARCStatus), DMARCDelegationID: stringValue(domain.DMARCDelegationID),
		DKIMStatus: stringValue(domain.DKIMStatus), DKIMDelegationID: stringValue(domain.DKIMDelegationID),
		SPFStatus: stringValue(domain.SPFStatus), SPFDelegationID: stringValue(domain.SPFDelegationID), IsPolicyInherited: boolValue(domain.IsPolicyInherited),
	}
	if domain.DNSRecords != nil {
		model.DNSA = dmarcDNSRecordDataSourceModels(domain.DNSRecords.A)
		model.DNSAAAA = dmarcDNSRecordDataSourceModels(domain.DNSRecords.AAAA)
		model.DNSCNAME = dmarcDNSRecordDataSourceModels(domain.DNSRecords.CNAME)
		model.DNSMX = dmarcDNSRecordDataSourceModels(domain.DNSRecords.MX)
		model.DNSNS = dmarcDNSRecordDataSourceModels(domain.DNSRecords.NS)
		model.DNSTXT = dmarcDNSRecordDataSourceModels(domain.DNSRecords.TXT)
		model.DNSPTR = dmarcDNSRecordDataSourceModels(domain.DNSRecords.PTR)
		model.DNSSRV = dmarcDNSRecordDataSourceModels(domain.DNSRecords.SRV)
		model.DNSSOA = dmarcDNSRecordDataSourceModels(domain.DNSRecords.SOA)
		model.DNSCAA = dmarcDNSRecordDataSourceModels(domain.DNSRecords.CAA)
		model.DNSDS = dmarcDNSRecordDataSourceModels(domain.DNSRecords.DS)
		model.DNSDNSKEY = dmarcDNSRecordDataSourceModels(domain.DNSRecords.DNSKEY)
		model.DNSDMARC = dmarcDNSRecordDataSourceModels(domain.DNSRecords.DMARC)
		model.DNSDKIM = dmarcDNSRecordDataSourceModels(domain.DNSRecords.DKIM)
	}
	return model
}

func NewDMARCDomainsDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable DMARC managed-domain inventory ID."), "items": dsItems(dmarcManagedDomainDataSourceAttributes())}
	return newTypedDataSource("dmarc_domains", "Read the complete typed DMARC Analyzer managed-domain inventory with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedDMARCDomains(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC Analyzer domains", err.Error())
			return
		}
		items := make([]dmarcManagedDomainDataSourceItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, dmarcManagedDomainDataSourceItem(item))
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dmarcManagedDomainsDataSourceModel{ID: types.StringValue("dmarc_domains"), Items: items})...)
	})
}

type dmarcReferenceDataSourceModel struct {
	ID     types.String `tfsdk:"id"`
	Domain types.String `tfsdk:"domain"`
	Name   types.String `tfsdk:"name"`
}

func dmarcReferenceDataSourceAttribute(description string) dsschema.ListNestedAttribute {
	return dsschema.ListNestedAttribute{
		Description: description,
		Computed:    true,
		NestedObject: dsschema.NestedAttributeObject{Attributes: map[string]dsschema.Attribute{
			"id": dsID("Referenced object ID."), "domain": dsString("Referenced domain name."), "name": dsString("Referenced object name."),
		}},
	}
}

func dmarcReferenceDataSourceModels(refs []client.DMARCDomainReference) []dmarcReferenceDataSourceModel {
	if refs == nil {
		return nil
	}
	canonical := append([]client.DMARCDomainReference(nil), refs...)
	sort.SliceStable(canonical, func(i, j int) bool {
		left := canonical[i].ID + "\x00" + canonical[i].Domain + "\x00" + canonical[i].Name
		right := canonical[j].ID + "\x00" + canonical[j].Domain + "\x00" + canonical[j].Name
		return left < right
	})
	items := make([]dmarcReferenceDataSourceModel, 0, len(canonical))
	for _, ref := range canonical {
		items = append(items, dmarcReferenceDataSourceModel{ID: stringValue(ref.ID), Domain: stringValue(ref.Domain), Name: stringValue(ref.Name)})
	}
	return items
}

type dmarcDomainGroupDataSourceItemModel struct {
	ID                           types.String                    `tfsdk:"id"`
	Name                         types.String                    `tfsdk:"name"`
	Type                         types.String                    `tfsdk:"type"`
	DoesAutoIncludeOrgSubdomains types.Bool                      `tfsdk:"does_auto_include_org_subdomains"`
	IncludeDomainsWithStatus     types.String                    `tfsdk:"include_domains_with_status"`
	IncludedDomains              []dmarcReferenceDataSourceModel `tfsdk:"included_domains"`
	IncludeDomainsRegex          types.Set                       `tfsdk:"include_domains_regex"`
	DomainsCount                 types.Int64                     `tfsdk:"domains_count"`
}

type dmarcDomainGroupsDataSourceModel struct {
	ID    types.String                          `tfsdk:"id"`
	Items []dmarcDomainGroupDataSourceItemModel `tfsdk:"items"`
}

func NewDMARCDomainGroupsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{
		"id": dsID("Domain-group ID."), "name": dsString("Domain-group name."), "type": dsString("Domain-group type."),
		"does_auto_include_org_subdomains": dsBool("Whether organisational subdomains are included automatically."),
		"include_domains_with_status":      dsString("Activity status used when automatically including domains."),
		"included_domains":                 dmarcReferenceDataSourceAttribute("Managed domains included in the group."),
		"include_domains_regex":            dsschema.SetAttribute{Description: "Domain patterns included by a dynamic group.", Computed: true, ElementType: types.StringType},
		"domains_count":                    dsInt64("Number of domains currently included in the group."),
	}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable DMARC domain-group inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("dmarc_domain_groups", "Read complete typed DMARC Analyzer domain groups with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedDMARCDomainGroups(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC Analyzer domain groups", err.Error())
			return
		}
		items := make([]dmarcDomainGroupDataSourceItemModel, 0, len(out))
		for _, item := range out {
			regex, regexDiags := dmarcDataSourceStringSet(ctx, item.IncludeDomainsRegex)
			resp.Diagnostics.Append(regexDiags...)
			items = append(items, dmarcDomainGroupDataSourceItemModel{
				ID: stringValue(item.ID), Name: stringValue(item.Name), Type: stringValue(item.Type),
				DoesAutoIncludeOrgSubdomains: boolValue(item.DoesAutoIncludeOrgSubdomains), IncludeDomainsWithStatus: stringValue(item.IncludeDomainsWithStatus),
				IncludedDomains: dmarcReferenceDataSourceModels(item.IncludedDomains), IncludeDomainsRegex: regex, DomainsCount: types.Int64Value(item.DomainsCount),
			})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dmarcDomainGroupsDataSourceModel{ID: types.StringValue("dmarc_domain_groups"), Items: items})...)
	})
}

type dmarcNotificationDataSourceItemModel struct {
	ID                       types.String                    `tfsdk:"id"`
	Emails                   types.Set                       `tfsdk:"emails"`
	Frequency                types.String                    `tfsdk:"frequency"`
	Type                     types.String                    `tfsdk:"type"`
	Domains                  []dmarcReferenceDataSourceModel `tfsdk:"domains"`
	Groups                   []dmarcReferenceDataSourceModel `tfsdk:"groups"`
	IsIndividualDomainAlert  types.Bool                      `tfsdk:"is_individual_domain_alert"`
	InvalidMessageEnabled    types.Bool                      `tfsdk:"invalid_message_enabled"`
	InvalidMessageThreshold  types.Int64                     `tfsdk:"invalid_message_threshold"`
	InvalidMessageInterval   types.String                    `tfsdk:"invalid_message_interval"`
	DMARCComplianceEnabled   types.Bool                      `tfsdk:"dmarc_compliance_enabled"`
	DMARCComplianceThreshold types.Int64                     `tfsdk:"dmarc_compliance_threshold"`
	DMARCComplianceInterval  types.String                    `tfsdk:"dmarc_compliance_interval"`
	ForensicMessageEnabled   types.Bool                      `tfsdk:"forensic_message_enabled"`
	ForensicMessageThreshold types.Int64                     `tfsdk:"forensic_message_threshold"`
	ForensicMessageInterval  types.String                    `tfsdk:"forensic_message_interval"`
	DNSDMARCRecords          types.Bool                      `tfsdk:"dns_dmarc_records"`
	DNSDKIMRecords           types.Bool                      `tfsdk:"dns_dkim_records"`
	DNSSPFRecords            types.Bool                      `tfsdk:"dns_spf_records"`
	NextTrigger              types.String                    `tfsdk:"next_trigger"`
}

type dmarcNotificationsDataSourceModel struct {
	ID    types.String                           `tfsdk:"id"`
	Items []dmarcNotificationDataSourceItemModel `tfsdk:"items"`
}

func dmarcNotificationDataSourceAttributes() map[string]dsschema.Attribute {
	return map[string]dsschema.Attribute{
		"id":        dsID("Notification ID."),
		"emails":    dsschema.SetAttribute{Description: "Notification recipient email addresses.", Computed: true, Sensitive: true, ElementType: types.StringType},
		"frequency": dsString("Notification frequency."), "type": dsString("Notification type."),
		"domains":                    dmarcReferenceDataSourceAttribute("Managed domains selected by the notification."),
		"groups":                     dmarcReferenceDataSourceAttribute("Domain groups selected by the notification."),
		"is_individual_domain_alert": dsBool("Whether compliance alerts are emitted for individual domains."),
		"invalid_message_enabled":    dsBool("Whether the invalid-message compliance trigger is enabled."),
		"invalid_message_threshold":  dsInt64("Invalid-message trigger threshold."),
		"invalid_message_interval":   dsString("Invalid-message trigger interval."),
		"dmarc_compliance_enabled":   dsBool("Whether the DMARC-compliance trigger is enabled."),
		"dmarc_compliance_threshold": dsInt64("DMARC-compliance trigger threshold."),
		"dmarc_compliance_interval":  dsString("DMARC-compliance trigger interval."),
		"forensic_message_enabled":   dsBool("Whether the forensic-message trigger is enabled."),
		"forensic_message_threshold": dsInt64("Forensic-message trigger threshold."),
		"forensic_message_interval":  dsString("Forensic-message trigger interval."),
		"dns_dmarc_records":          dsBool("Whether the DNS monitor checks DMARC records."),
		"dns_dkim_records":           dsBool("Whether the DNS monitor checks DKIM records."),
		"dns_spf_records":            dsBool("Whether the DNS monitor checks SPF records."),
		"next_trigger":               dsString("Next scheduled notification trigger timestamp."),
	}
}

func dmarcNotificationDataSourceItem(ctx context.Context, item client.ManagedDMARCNotification, diags *diag.Diagnostics) dmarcNotificationDataSourceItemModel {
	emails, emailDiags := dmarcDataSourceStringSet(ctx, item.Emails)
	diags.Append(emailDiags...)
	model := dmarcNotificationDataSourceItemModel{
		ID: stringValue(item.ID), Emails: emails, Frequency: stringValue(item.Frequency), Type: stringValue(item.Type),
		Domains: dmarcReferenceDataSourceModels(item.Domains), Groups: dmarcReferenceDataSourceModels(item.Groups), NextTrigger: stringValue(item.NextTrigger),
	}
	if item.TriggerConfig != nil {
		config := item.TriggerConfig
		model.IsIndividualDomainAlert = boolValue(config.IsIndividualDomainAlert)
		dmarcDataSourceComplianceTrigger(config.InvalidMessageTrigger, &model.InvalidMessageEnabled, &model.InvalidMessageThreshold, &model.InvalidMessageInterval)
		dmarcDataSourceComplianceTrigger(config.DMARCComplianceTrigger, &model.DMARCComplianceEnabled, &model.DMARCComplianceThreshold, &model.DMARCComplianceInterval)
		dmarcDataSourceComplianceTrigger(config.ForensicMessageTrigger, &model.ForensicMessageEnabled, &model.ForensicMessageThreshold, &model.ForensicMessageInterval)
		model.DNSDMARCRecords = boolValue(config.DMARCRecords)
		model.DNSDKIMRecords = boolValue(config.DKIMRecords)
		model.DNSSPFRecords = boolValue(config.SPFRecords)
	}
	return model
}

func dmarcDataSourceComplianceTrigger(trigger *client.DMARCComplianceTrigger, enabled *types.Bool, threshold *types.Int64, interval *types.String) {
	if trigger == nil {
		*enabled, *threshold, *interval = types.BoolNull(), types.Int64Null(), types.StringNull()
		return
	}
	*enabled = boolValue(trigger.Enabled)
	*threshold = dmarcDataSourceInt64Value(trigger.Threshold)
	*interval = stringValue(trigger.Interval)
}

func NewDMARCNotificationsDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable DMARC notification inventory ID."), "items": dsItems(dmarcNotificationDataSourceAttributes())}
	return newTypedDataSource("dmarc_notifications", "Read complete typed DMARC Analyzer notification configuration with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedDMARCNotifications(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC Analyzer notifications", err.Error())
			return
		}
		items := make([]dmarcNotificationDataSourceItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, dmarcNotificationDataSourceItem(ctx, item, &resp.Diagnostics))
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dmarcNotificationsDataSourceModel{ID: types.StringValue("dmarc_notifications"), Items: items})...)
	})
}

type dmarcDelegatedDomainDataSourceItemModel struct {
	ID                    types.String `tfsdk:"id"`
	Domain                types.String `tfsdk:"domain"`
	Hash                  types.String `tfsdk:"hash"`
	DMARCDelegationStatus types.String `tfsdk:"dmarc_delegation_status"`
	DMARCPolicy           types.String `tfsdk:"dmarc_policy"`
	DKIMDelegationStatus  types.String `tfsdk:"dkim_delegation_status"`
	SPFDelegationStatus   types.String `tfsdk:"spf_delegation_status"`
	Details               types.String `tfsdk:"details"`
}

type dmarcDelegatedDomainsDataSourceModel struct {
	ID    types.String                              `tfsdk:"id"`
	Items []dmarcDelegatedDomainDataSourceItemModel `tfsdk:"items"`
}

func NewDMARCDelegatedDomainsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{
		"id": dsID("Delegated-domain ID."), "domain": dsString("Domain name."), "hash": dsString("Delegation hash."),
		"dmarc_delegation_status": dsString("DMARC delegation status."), "dmarc_policy": dsString("DMARC policy."),
		"dkim_delegation_status": dsString("DKIM delegation status."), "spf_delegation_status": dsString("SPF delegation status."),
		"details": dsString("Delegated-domain status details."),
	}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable delegated-domain inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("dmarc_delegated_domains", "Read complete typed DMARC Analyzer delegated-domain configuration with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedDMARCDelegatedDomains(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC Analyzer delegated domains", err.Error())
			return
		}
		items := make([]dmarcDelegatedDomainDataSourceItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, dmarcDelegatedDomainDataSourceItemModel{
				ID: stringValue(item.ID), Domain: stringValue(item.Domain), Hash: stringValue(item.Hash),
				DMARCDelegationStatus: stringValue(item.DMARCDelegationStatus), DMARCPolicy: stringValue(item.DMARCPolicy),
				DKIMDelegationStatus: stringValue(item.DKIMDelegationStatus), SPFDelegationStatus: stringValue(item.SPFDelegationStatus), Details: stringValue(item.Details),
			})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dmarcDelegatedDomainsDataSourceModel{ID: types.StringValue("dmarc_delegated_domains"), Items: items})...)
	})
}

type dmarcPolicyPresetDataSourceItemModel struct {
	ID                      types.String `tfsdk:"id"`
	Name                    types.String `tfsdk:"name"`
	IsDefaultPolicy         types.Bool   `tfsdk:"is_default_policy"`
	Description             types.String `tfsdk:"description"`
	Version                 types.String `tfsdk:"version"`
	Policy                  types.String `tfsdk:"policy"`
	SubdomainPolicy         types.String `tfsdk:"subdomain_policy"`
	Percentage              types.Int64  `tfsdk:"percentage"`
	DKIMAlignment           types.String `tfsdk:"dkim_alignment"`
	SPFAlignment            types.String `tfsdk:"spf_alignment"`
	ReportInterval          types.Int64  `tfsdk:"report_interval"`
	RUAAddresses            types.Set    `tfsdk:"rua_addresses"`
	RUFAddresses            types.Set    `tfsdk:"ruf_addresses"`
	FailureReportingOptions types.String `tfsdk:"failure_reporting_options"`
	FailureReportFormat     types.String `tfsdk:"failure_report_format"`
}

type dmarcPolicyPresetsDataSourceModel struct {
	ID    types.String                           `tfsdk:"id"`
	Items []dmarcPolicyPresetDataSourceItemModel `tfsdk:"items"`
}

func NewDMARCPolicyPresetsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{
		"id": dsID("Preset ID."), "name": dsString("Preset name."), "is_default_policy": dsBool("Whether this is the default preset."),
		"description": dsString("Preset description."), "version": dsString("DMARC definition version."), "policy": dsString("DMARC policy action."),
		"subdomain_policy": dsString("DMARC subdomain policy action."), "percentage": dsInt64("Policy application percentage."),
		"dkim_alignment": dsString("DKIM alignment mode."), "spf_alignment": dsString("SPF alignment mode."), "report_interval": dsInt64("Aggregate report interval."),
		"rua_addresses":             dsschema.SetAttribute{Description: "Aggregate report recipients.", Computed: true, Sensitive: true, ElementType: types.StringType},
		"ruf_addresses":             dsschema.SetAttribute{Description: "Forensic report recipients.", Computed: true, Sensitive: true, ElementType: types.StringType},
		"failure_reporting_options": dsString("Colon-delimited DMARC failure reporting options."), "failure_report_format": dsString("DMARC failure report format."),
	}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable DMARC policy-preset inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("dmarc_policy_presets", "Read complete typed DMARC Analyzer policy presets with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedDMARCPolicyPresets(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC Analyzer policy presets", err.Error())
			return
		}
		items := make([]dmarcPolicyPresetDataSourceItemModel, 0, len(out))
		for _, item := range out {
			rua, ruaDiags := dmarcDataSourceStringSetPointer(ctx, item.RUAAddresses)
			ruf, rufDiags := dmarcDataSourceStringSetPointer(ctx, item.RUFAddresses)
			resp.Diagnostics.Append(ruaDiags...)
			resp.Diagnostics.Append(rufDiags...)
			items = append(items, dmarcPolicyPresetDataSourceItemModel{
				ID: stringValue(item.ID), Name: stringValue(item.Name), IsDefaultPolicy: boolValue(item.IsDefaultPolicy), Description: stringValue(item.Description),
				Version: stringValue(item.Version), Policy: stringValue(item.Policy), SubdomainPolicy: stringValue(item.SubdomainPolicy), Percentage: dmarcDataSourceInt64Value(item.Percentage),
				DKIMAlignment: stringValue(item.DKIMAlignment), SPFAlignment: stringValue(item.SPFAlignment), ReportInterval: dmarcDataSourceInt64Value(item.ReportInterval),
				RUAAddresses: rua, RUFAddresses: ruf, FailureReportingOptions: stringValue(item.FailureReportingOptions), FailureReportFormat: stringValue(item.FailureReportFormat),
			})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dmarcPolicyPresetsDataSourceModel{ID: types.StringValue("dmarc_policy_presets"), Items: items})...)
	})
}

type dmarcUserDataSourceItemModel struct {
	ID                     types.String                    `tfsdk:"id"`
	UserName               types.String                    `tfsdk:"user_name"`
	UserEmail              types.String                    `tfsdk:"user_email"`
	UserPermission         types.String                    `tfsdk:"user_permission"`
	AllowedGroups          []dmarcUserGroupDataSourceModel `tfsdk:"allowed_groups"`
	AggregateReports       types.Bool                      `tfsdk:"aggregate_reports"`
	AlertsAndNotifications types.Bool                      `tfsdk:"alerts_and_notifications"`
	DNSDelegation          types.Bool                      `tfsdk:"dns_delegation"`
	DNSChecker             types.Bool                      `tfsdk:"dns_checker"`
	DNSGenerator           types.Bool                      `tfsdk:"dns_generator"`
	DomainManagement       types.Bool                      `tfsdk:"domain_management"`
	EncryptionPGPKey       types.Bool                      `tfsdk:"encryption_pgp_key"`
	ForensicReports        types.Bool                      `tfsdk:"forensic_reports"`
	Reporting              types.Bool                      `tfsdk:"reporting"`
	TaskManager            types.Bool                      `tfsdk:"task_manager"`
	Timeline               types.Bool                      `tfsdk:"timeline"`
	TLSReports             types.Bool                      `tfsdk:"tls_reports"`
	UserManagement         types.Bool                      `tfsdk:"user_management"`
	VendorManagement       types.Bool                      `tfsdk:"vendor_management"`
}

type dmarcUserGroupDataSourceModel struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
	Type types.String `tfsdk:"type"`
}

type dmarcUsersDataSourceModel struct {
	ID    types.String                   `tfsdk:"id"`
	Items []dmarcUserDataSourceItemModel `tfsdk:"items"`
}

func dmarcUserDataSourceAttributes() map[string]dsschema.Attribute {
	return map[string]dsschema.Attribute{
		"id": dsID("DMARC Analyzer user ID."), "user_name": dsSensitiveString("User name."), "user_email": dsSensitiveString("User email address."),
		"user_permission": dsString("User permission level."),
		"allowed_groups": dsschema.ListNestedAttribute{Description: "Domain groups the user may access.", Computed: true, NestedObject: dsschema.NestedAttributeObject{Attributes: map[string]dsschema.Attribute{
			"id": dsID("Domain-group ID."), "name": dsString("Domain-group name."), "type": dsString("Domain-group type."),
		}}},
		"aggregate_reports":        dsBool("Whether the user can access aggregate reports."),
		"alerts_and_notifications": dsBool("Whether the user can access alerts and notifications."),
		"dns_delegation":           dsBool("Whether the user can access DNS delegation."), "dns_checker": dsBool("Whether the user can access the DNS checker."),
		"dns_generator": dsBool("Whether the user can access the DNS generator."), "domain_management": dsBool("Whether the user can access domain management."),
		"encryption_pgp_key": dsBool("Whether the user can access encryption PGP keys."), "forensic_reports": dsBool("Whether the user can access forensic reports."),
		"reporting": dsBool("Whether the user can access reporting."), "task_manager": dsBool("Whether the user can access task management."),
		"timeline": dsBool("Whether the user can access the timeline."), "tls_reports": dsBool("Whether the user can access SMTP TLS reports."),
		"user_management": dsBool("Whether the user can access user management."), "vendor_management": dsBool("Whether the user can access vendor management."),
	}
}

func dmarcUserDataSourceItem(item client.ManagedDMARCUser) dmarcUserDataSourceItemModel {
	groups := append([]client.DMARCUserDomainGroup(nil), item.AllowedGroups...)
	sort.SliceStable(groups, func(i, j int) bool {
		left := groups[i].ID + "\x00" + groups[i].Name + "\x00" + groups[i].Type
		right := groups[j].ID + "\x00" + groups[j].Name + "\x00" + groups[j].Type
		return left < right
	})
	allowedGroups := make([]dmarcUserGroupDataSourceModel, 0, len(groups))
	for _, group := range groups {
		allowedGroups = append(allowedGroups, dmarcUserGroupDataSourceModel{ID: stringValue(group.ID), Name: stringValue(group.Name), Type: stringValue(group.Type)})
	}
	model := dmarcUserDataSourceItemModel{
		ID: stringValue(item.ID), UserName: stringValue(item.UserName), UserEmail: stringValue(item.UserEmail),
		UserPermission: stringValue(item.UserPermission), AllowedGroups: allowedGroups,
	}
	if item.Features != nil {
		features := item.Features
		model.AggregateReports = boolValue(features.AggregateReports)
		model.AlertsAndNotifications = boolValue(features.AlertsAndNotifications)
		model.DNSDelegation = boolValue(features.DNSDelegation)
		model.DNSChecker = boolValue(features.DNSChecker)
		model.DNSGenerator = boolValue(features.DNSGenerator)
		model.DomainManagement = boolValue(features.DomainManagement)
		model.EncryptionPGPKey = boolValue(features.EncryptionPGPKey)
		model.ForensicReports = boolValue(features.ForensicReports)
		model.Reporting = boolValue(features.Reporting)
		model.TaskManager = boolValue(features.TaskManager)
		model.Timeline = boolValue(features.Timeline)
		model.TLSReports = boolValue(features.TLSReports)
		model.UserManagement = boolValue(features.UserManagement)
		model.VendorManagement = boolValue(features.VendorManagement)
	}
	return model
}

func NewDMARCUsersDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable DMARC Analyzer user inventory ID."), "items": dsItems(dmarcUserDataSourceAttributes())}
	return newTypedDataSource("dmarc_users", "Read all DMARC Analyzer users, group access, and feature permissions with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedDMARCUsers(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC Analyzer users", err.Error())
			return
		}
		items := make([]dmarcUserDataSourceItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, dmarcUserDataSourceItem(item))
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dmarcUsersDataSourceModel{ID: types.StringValue("dmarc_users"), Items: items})...)
	})
}

func dmarcDataSourceStringSet(ctx context.Context, values []string) (types.Set, diag.Diagnostics) {
	if values == nil {
		return types.SetNull(types.StringType), nil
	}
	canonical := append([]string(nil), values...)
	sort.Strings(canonical)
	return setFromStrings(ctx, canonical)
}

func dmarcDataSourceStringSetPointer(ctx context.Context, values *[]string) (types.Set, diag.Diagnostics) {
	if values == nil {
		return types.SetNull(types.StringType), nil
	}
	return dmarcDataSourceStringSet(ctx, *values)
}

func dmarcDataSourceInt64Value(value *int64) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*value)
}
