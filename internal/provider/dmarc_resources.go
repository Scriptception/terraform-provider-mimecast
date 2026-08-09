package provider

import (
	"context"
	"fmt"
	"net/mail"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

var dmarcDNSRecordObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"domain":   types.StringType,
	"value":    types.StringType,
	"selector": types.StringType,
}}

type dmarcDNSRecordModel struct {
	Domain   types.String `tfsdk:"domain"`
	Value    types.String `tfsdk:"value"`
	Selector types.String `tfsdk:"selector"`
}

func dmarcDNSRecordAttribute(description string) schema.SetNestedAttribute {
	return schema.SetNestedAttribute{
		Description: description,
		Computed:    true,
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"domain":   schema.StringAttribute{Description: "DNS record owner name.", Computed: true},
			"value":    schema.StringAttribute{Description: "DNS record value.", Computed: true},
			"selector": schema.StringAttribute{Description: "DKIM selector when applicable.", Computed: true},
		}},
	}
}

func dmarcDNSRecordSet(ctx context.Context, records []client.DMARCDNSRecordValue) (types.Set, diag.Diagnostics) {
	if records == nil {
		return types.SetNull(dmarcDNSRecordObjectType), nil
	}
	models := make([]dmarcDNSRecordModel, 0, len(records))
	for _, record := range records {
		models = append(models, dmarcDNSRecordModel{
			Domain:   stringValue(record.Domain),
			Value:    stringValue(record.Value),
			Selector: stringValue(record.Selector),
		})
	}
	return types.SetValueFrom(ctx, dmarcDNSRecordObjectType, models)
}

func dmarcStringsFromSet(ctx context.Context, value types.Set) ([]string, diag.Diagnostics) {
	items, diags := stringsFromSet(ctx, value)
	sort.Strings(items)
	return items, diags
}

func dmarcOptionalStringSetPointer(ctx context.Context, value types.Set) (*[]string, diag.Diagnostics) {
	if value.IsNull() || value.IsUnknown() {
		return nil, nil
	}
	items, diags := dmarcStringsFromSet(ctx, value)
	return &items, diags
}

func dmarcSetFromPointer(ctx context.Context, values *[]string) (types.Set, diag.Diagnostics) {
	if values == nil {
		return types.SetNull(types.StringType), nil
	}
	items := append([]string(nil), (*values)...)
	sort.Strings(items)
	return setFromStrings(ctx, items)
}

func dmarcInt64Pointer(value types.Int64) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueInt64()
	return &result
}

func dmarcInt64Value(value *int64) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*value)
}

// ---- Managed domain -------------------------------------------------------

type dmarcManagedDomainResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Domain            types.String `tfsdk:"domain"`
	ActivityStatus    types.String `tfsdk:"activity_status"`
	DetectedStatus    types.String `tfsdk:"detected_status"`
	Status            types.String `tfsdk:"status"`
	DMARCPolicy       types.String `tfsdk:"dmarc_policy"`
	DMARCStatus       types.String `tfsdk:"dmarc_status"`
	DMARCDelegationID types.String `tfsdk:"dmarc_delegation_id"`
	DKIMStatus        types.String `tfsdk:"dkim_status"`
	DKIMDelegationID  types.String `tfsdk:"dkim_delegation_id"`
	SPFStatus         types.String `tfsdk:"spf_status"`
	SPFDelegationID   types.String `tfsdk:"spf_delegation_id"`
	IsPolicyInherited types.Bool   `tfsdk:"is_policy_inherited"`
	DNSA              types.Set    `tfsdk:"dns_a_records"`
	DNSAAAA           types.Set    `tfsdk:"dns_aaaa_records"`
	DNSCNAME          types.Set    `tfsdk:"dns_cname_records"`
	DNSMX             types.Set    `tfsdk:"dns_mx_records"`
	DNSNS             types.Set    `tfsdk:"dns_ns_records"`
	DNSTXT            types.Set    `tfsdk:"dns_txt_records"`
	DNSPTR            types.Set    `tfsdk:"dns_ptr_records"`
	DNSSRV            types.Set    `tfsdk:"dns_srv_records"`
	DNSSOA            types.Set    `tfsdk:"dns_soa_records"`
	DNSCAA            types.Set    `tfsdk:"dns_caa_records"`
	DNSDS             types.Set    `tfsdk:"dns_ds_records"`
	DNSDNSKEY         types.Set    `tfsdk:"dns_dnskey_records"`
	DNSDMARC          types.Set    `tfsdk:"dns_dmarc_records"`
	DNSDKIM           types.Set    `tfsdk:"dns_dkim_records"`
}

type dmarcManagedDomainResource struct{ client *client.Client }

// NewDMARCManagedDomainResource manages a Mimecast DMARC Analyzer domain.
func NewDMARCManagedDomainResource() resource.Resource { return &dmarcManagedDomainResource{} }

func (r *dmarcManagedDomainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_managed_domain"
}

func (r *dmarcManagedDomainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast DMARC Analyzer managed domain.", Attributes: map[string]schema.Attribute{
		"id":     idAttr("DMARC Analyzer managed-domain ID."),
		"domain": requiredReplaceString("Managed domain name. Mimecast does not expose an update operation for this field."),
		"activity_status": schema.StringAttribute{
			Description: "Managed-domain activity status.", Optional: true, Computed: true,
			Validators:    []validator.String{stringvalidator.OneOf("active", "inactive")},
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"detected_status":     computedString("Detected-domain activity status."),
		"status":              computedString("Managed-domain lifecycle stage."),
		"dmarc_policy":        computedString("Published DMARC policy."),
		"dmarc_status":        computedString("DMARC DNS configuration status."),
		"dmarc_delegation_id": computedString("DMARC delegation record ID."),
		"dkim_status":         computedString("DKIM DNS configuration status."),
		"dkim_delegation_id":  computedString("DKIM delegation record ID."),
		"spf_status":          computedString("SPF DNS configuration status."),
		"spf_delegation_id":   computedString("SPF delegation record ID."),
		"is_policy_inherited": schema.BoolAttribute{Description: "Whether the DMARC policy is inherited from a parent domain.", Computed: true},
		"dns_a_records":       dmarcDNSRecordAttribute("A records returned for the domain."),
		"dns_aaaa_records":    dmarcDNSRecordAttribute("AAAA records returned for the domain."),
		"dns_cname_records":   dmarcDNSRecordAttribute("CNAME records returned for the domain."),
		"dns_mx_records":      dmarcDNSRecordAttribute("MX records returned for the domain."),
		"dns_ns_records":      dmarcDNSRecordAttribute("NS records returned for the domain."),
		"dns_txt_records":     dmarcDNSRecordAttribute("TXT records returned for the domain."),
		"dns_ptr_records":     dmarcDNSRecordAttribute("PTR records returned for the domain."),
		"dns_srv_records":     dmarcDNSRecordAttribute("SRV records returned for the domain."),
		"dns_soa_records":     dmarcDNSRecordAttribute("SOA records returned for the domain."),
		"dns_caa_records":     dmarcDNSRecordAttribute("CAA records returned for the domain."),
		"dns_ds_records":      dmarcDNSRecordAttribute("DS records returned for the domain."),
		"dns_dnskey_records":  dmarcDNSRecordAttribute("DNSKEY records returned for the domain."),
		"dns_dmarc_records":   dmarcDNSRecordAttribute("DMARC records returned for the domain."),
		"dns_dkim_records":    dmarcDNSRecordAttribute("DKIM records returned for the domain."),
	}}
}

func (r *dmarcManagedDomainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcManagedDomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcManagedDomainResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateManagedDMARCDomain(ctx, plan.Domain.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC managed domain", err.Error())
		return
	}
	created, err := r.client.GetManagedDMARCDomain(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC managed domain", err.Error())
		return
	}
	if !plan.ActivityStatus.IsNull() && !plan.ActivityStatus.IsUnknown() && plan.ActivityStatus.ValueString() != created.ActivityStatus {
		if err := r.client.UpdateManagedDMARCDomain(ctx, id, plan.ActivityStatus.ValueString()); err != nil {
			resp.Diagnostics.AddError("Unable to set created DMARC managed domain activity status", err.Error())
			return
		}
		created, err = r.client.GetManagedDMARCDomain(ctx, id)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read updated DMARC managed domain", err.Error())
			return
		}
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcManagedDomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcManagedDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCDomain(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC managed domain", err.Error())
		return
	}
	state.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcManagedDomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dmarcManagedDomainResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateManagedDMARCDomain(ctx, plan.ID.ValueString(), plan.ActivityStatus.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to update DMARC managed domain", err.Error())
		return
	}
	updated, err := r.client.GetManagedDMARCDomain(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated DMARC managed domain", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcManagedDomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcManagedDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCDomain(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC managed domain", err.Error())
	}
}

func (r *dmarcManagedDomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (model *dmarcManagedDomainResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCDomain, diags *diag.Diagnostics) {
	model.ID = stringValue(result.ID)
	model.Domain = stringValue(result.Domain)
	model.ActivityStatus = stringValue(result.ActivityStatus)
	model.DetectedStatus = stringValue(result.DetectedStatus)
	model.Status = stringValue(result.Status)
	model.DMARCPolicy = stringValue(result.DMARCPolicy)
	model.DMARCStatus = stringValue(result.DMARCStatus)
	model.DMARCDelegationID = stringValue(result.DMARCDelegationID)
	model.DKIMStatus = stringValue(result.DKIMStatus)
	model.DKIMDelegationID = stringValue(result.DKIMDelegationID)
	model.SPFStatus = stringValue(result.SPFStatus)
	model.SPFDelegationID = stringValue(result.SPFDelegationID)
	model.IsPolicyInherited = boolValue(result.IsPolicyInherited)
	var records client.DMARCDNSRecords
	if result.DNSRecords != nil {
		records = *result.DNSRecords
	}
	values := []struct {
		target *types.Set
		items  []client.DMARCDNSRecordValue
	}{
		{&model.DNSA, records.A}, {&model.DNSAAAA, records.AAAA}, {&model.DNSCNAME, records.CNAME},
		{&model.DNSMX, records.MX}, {&model.DNSNS, records.NS}, {&model.DNSTXT, records.TXT},
		{&model.DNSPTR, records.PTR}, {&model.DNSSRV, records.SRV}, {&model.DNSSOA, records.SOA},
		{&model.DNSCAA, records.CAA}, {&model.DNSDS, records.DS}, {&model.DNSDNSKEY, records.DNSKEY},
		{&model.DNSDMARC, records.DMARC}, {&model.DNSDKIM, records.DKIM},
	}
	for _, value := range values {
		if result.DNSRecords == nil {
			*value.target = types.SetNull(dmarcDNSRecordObjectType)
			continue
		}
		set, setDiags := dmarcDNSRecordSet(ctx, value.items)
		*value.target = set
		diags.Append(setDiags...)
	}
}

// ---- Domain group ---------------------------------------------------------

type dmarcDomainGroupResourceModel struct {
	ID                           types.String `tfsdk:"id"`
	Name                         types.String `tfsdk:"name"`
	Type                         types.String `tfsdk:"type"`
	DoesAutoIncludeOrgSubdomains types.Bool   `tfsdk:"does_auto_include_org_subdomains"`
	IncludeDomainsWithStatus     types.String `tfsdk:"include_domains_with_status"`
	IncludedDomainIDs            types.Set    `tfsdk:"included_domain_ids"`
	IncludeDomainsRegex          types.Set    `tfsdk:"include_domains_regex"`
	DomainsCount                 types.Int64  `tfsdk:"domains_count"`
}

type dmarcDomainGroupResource struct{ client *client.Client }

// NewDMARCDomainGroupResource manages a Mimecast DMARC Analyzer domain group.
func NewDMARCDomainGroupResource() resource.Resource { return &dmarcDomainGroupResource{} }

func (r *dmarcDomainGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_domain_group"
}

func (r *dmarcDomainGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast DMARC Analyzer domain group.", Attributes: map[string]schema.Attribute{
		"id":                               idAttr("DMARC Analyzer domain-group ID."),
		"name":                             schema.StringAttribute{Description: "Domain-group name.", Required: true, Validators: []validator.String{stringvalidator.LengthAtMost(100)}},
		"type":                             schema.StringAttribute{Description: "Domain-group type.", Required: true, Validators: []validator.String{stringvalidator.OneOf("static", "dynamic")}},
		"does_auto_include_org_subdomains": schema.BoolAttribute{Description: "Whether organisational subdomains are included automatically.", Optional: true, Computed: true},
		"include_domains_with_status": schema.StringAttribute{
			Description: "Activity status used when automatically including domains.", Optional: true, Computed: true,
			Validators:    []validator.String{stringvalidator.OneOf("active", "inactive")},
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"included_domain_ids": schema.SetAttribute{
			Description: "Managed-domain IDs included in the group.", Optional: true, Computed: true, ElementType: types.StringType,
			Validators: []validator.Set{setvalidator.SizeAtMost(10)}, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"include_domains_regex": schema.SetAttribute{
			Description: "Domain patterns included by a dynamic group.", Optional: true, Computed: true, ElementType: types.StringType,
			Validators: []validator.Set{setvalidator.SizeAtMost(1)}, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"domains_count": schema.Int64Attribute{Description: "Number of domains currently included in the group.", Computed: true},
	}}
}

func (r *dmarcDomainGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcDomainGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcDomainGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateManagedDMARCDomainGroup(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC domain group", err.Error())
		return
	}
	created, err := r.client.GetManagedDMARCDomainGroup(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC domain group", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDomainGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcDomainGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCDomainGroup(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC domain group", err.Error())
		return
	}
	state.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcDomainGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dmarcDomainGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateManagedDMARCDomainGroup(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update DMARC domain group", err.Error())
		return
	}
	updated, err := r.client.GetManagedDMARCDomainGroup(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated DMARC domain group", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDomainGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcDomainGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCDomainGroup(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC domain group", err.Error())
	}
}

func (r *dmarcDomainGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (model dmarcDomainGroupResourceModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.DMARCDomainGroupRequest {
	includedDomains, includedDiags := dmarcOptionalStringSetPointer(ctx, model.IncludedDomainIDs)
	includeRegex, regexDiags := dmarcOptionalStringSetPointer(ctx, model.IncludeDomainsRegex)
	diags.Append(includedDiags...)
	diags.Append(regexDiags...)
	return client.DMARCDomainGroupRequest{
		Name:                         model.Name.ValueString(),
		Type:                         model.Type.ValueString(),
		DoesAutoIncludeOrgSubdomains: boolPtr(model.DoesAutoIncludeOrgSubdomains),
		IncludeDomainsWithStatus:     model.IncludeDomainsWithStatus.ValueString(),
		IncludedDomains:              includedDomains,
		IncludeDomainsRegex:          includeRegex,
	}
}

func (model *dmarcDomainGroupResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCDomainGroup, diags *diag.Diagnostics) {
	model.ID = stringValue(result.ID)
	model.Name = stringValue(result.Name)
	model.Type = stringValue(result.Type)
	model.DoesAutoIncludeOrgSubdomains = boolValue(result.DoesAutoIncludeOrgSubdomains)
	model.IncludeDomainsWithStatus = stringValue(result.IncludeDomainsWithStatus)
	ids := make([]string, 0, len(result.IncludedDomains))
	for _, domain := range result.IncludedDomains {
		if domain.ID != "" {
			ids = append(ids, domain.ID)
		}
	}
	sort.Strings(ids)
	var setDiags diag.Diagnostics
	model.IncludedDomainIDs, setDiags = setFromStrings(ctx, ids)
	diags.Append(setDiags...)
	model.IncludeDomainsRegex, setDiags = setFromStrings(ctx, result.IncludeDomainsRegex)
	diags.Append(setDiags...)
	model.DomainsCount = types.Int64Value(result.DomainsCount)
}

// ---- Notification ---------------------------------------------------------

type dmarcNotificationResourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Type                     types.String `tfsdk:"type"`
	Emails                   types.Set    `tfsdk:"emails"`
	Frequency                types.String `tfsdk:"frequency"`
	DomainIDs                types.Set    `tfsdk:"domain_ids"`
	GroupIDs                 types.Set    `tfsdk:"group_ids"`
	IsIndividualDomainAlert  types.Bool   `tfsdk:"is_individual_domain_alert"`
	InvalidMessageEnabled    types.Bool   `tfsdk:"invalid_message_enabled"`
	InvalidMessageThreshold  types.Int64  `tfsdk:"invalid_message_threshold"`
	InvalidMessageInterval   types.String `tfsdk:"invalid_message_interval"`
	DMARCComplianceEnabled   types.Bool   `tfsdk:"dmarc_compliance_enabled"`
	DMARCComplianceThreshold types.Int64  `tfsdk:"dmarc_compliance_threshold"`
	DMARCComplianceInterval  types.String `tfsdk:"dmarc_compliance_interval"`
	ForensicMessageEnabled   types.Bool   `tfsdk:"forensic_message_enabled"`
	ForensicMessageThreshold types.Int64  `tfsdk:"forensic_message_threshold"`
	ForensicMessageInterval  types.String `tfsdk:"forensic_message_interval"`
	DNSDMARCRecords          types.Bool   `tfsdk:"dns_dmarc_records"`
	DNSDKIMRecords           types.Bool   `tfsdk:"dns_dkim_records"`
	DNSSPFRecords            types.Bool   `tfsdk:"dns_spf_records"`
	NextTrigger              types.String `tfsdk:"next_trigger"`
}

type dmarcNotificationResource struct{ client *client.Client }

// NewDMARCNotificationResource manages a Mimecast DMARC Analyzer notification.
func NewDMARCNotificationResource() resource.Resource { return &dmarcNotificationResource{} }

func (r *dmarcNotificationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_notification"
}

func dmarcOptionalComputedFrequency(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Description: description, Optional: true, Computed: true,
		Validators:    []validator.String{stringvalidator.OneOf("daily", "weekly", "monthly")},
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func (r *dmarcNotificationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast DMARC Analyzer notification.", Attributes: map[string]schema.Attribute{
		"id": idAttr("DMARC Analyzer notification ID."),
		"type": schema.StringAttribute{
			Description: "Notification type. Mimecast encodes this in the create path and does not expose an update operation for it.", Required: true,
			Validators:    []validator.String{stringvalidator.OneOf("dmarcSummary", "complianceMonitor", "dnsMonitor")},
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"emails": schema.SetAttribute{
			Description: "Notification recipient email address. The API accepts exactly one address.", Required: true, Sensitive: true, ElementType: types.StringType,
			Validators: []validator.Set{setvalidator.SizeBetween(1, 1), dmarcEmailSetValidator{}},
		},
		"frequency": dmarcOptionalComputedFrequency("Notification frequency."),
		"domain_ids": schema.SetAttribute{
			Description: "Managed-domain IDs selected by the notification.", Optional: true, Computed: true, ElementType: types.StringType,
			Validators: []validator.Set{setvalidator.SizeAtMost(1)}, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"group_ids": schema.SetAttribute{
			Description: "Domain-group IDs selected by the notification.", Optional: true, Computed: true, ElementType: types.StringType,
			Validators: []validator.Set{setvalidator.SizeAtMost(1)}, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"is_individual_domain_alert": optionalComputedBool("Whether compliance alerts are emitted for individual domains."),
		"invalid_message_enabled":    optionalComputedBool("Whether the invalid-message compliance trigger is enabled."),
		"invalid_message_threshold":  optionalComputedInt64("Invalid-message trigger threshold."),
		"invalid_message_interval":   dmarcOptionalComputedFrequency("Invalid-message trigger interval."),
		"dmarc_compliance_enabled":   optionalComputedBool("Whether the DMARC-compliance trigger is enabled."),
		"dmarc_compliance_threshold": optionalComputedInt64("DMARC-compliance trigger threshold."),
		"dmarc_compliance_interval":  dmarcOptionalComputedFrequency("DMARC-compliance trigger interval."),
		"forensic_message_enabled":   optionalComputedBool("Whether the forensic-message trigger is enabled."),
		"forensic_message_threshold": optionalComputedInt64("Forensic-message trigger threshold."),
		"forensic_message_interval":  dmarcOptionalComputedFrequency("Forensic-message trigger interval."),
		"dns_dmarc_records":          optionalComputedBool("Whether the DNS monitor checks DMARC records."),
		"dns_dkim_records":           optionalComputedBool("Whether the DNS monitor checks DKIM records."),
		"dns_spf_records":            optionalComputedBool("Whether the DNS monitor checks SPF records."),
		"next_trigger":               computedString("Next scheduled notification trigger timestamp."),
	}}
}

func (r *dmarcNotificationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcNotificationResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config dmarcNotificationResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Type.IsNull() || config.Type.IsUnknown() {
		return
	}
	validateDMARCNotificationModel(config, &resp.Diagnostics)
}

func validateDMARCNotificationModel(config dmarcNotificationResourceModel, diags *diag.Diagnostics) {
	complianceFields := []struct {
		name       string
		configured bool
	}{
		{"is_individual_domain_alert", dmarcBoolConfigured(config.IsIndividualDomainAlert)},
		{"invalid_message_enabled", dmarcBoolConfigured(config.InvalidMessageEnabled)},
		{"invalid_message_threshold", dmarcInt64Configured(config.InvalidMessageThreshold)},
		{"invalid_message_interval", dmarcStringConfigured(config.InvalidMessageInterval)},
		{"dmarc_compliance_enabled", dmarcBoolConfigured(config.DMARCComplianceEnabled)},
		{"dmarc_compliance_threshold", dmarcInt64Configured(config.DMARCComplianceThreshold)},
		{"dmarc_compliance_interval", dmarcStringConfigured(config.DMARCComplianceInterval)},
		{"forensic_message_enabled", dmarcBoolConfigured(config.ForensicMessageEnabled)},
		{"forensic_message_threshold", dmarcInt64Configured(config.ForensicMessageThreshold)},
		{"forensic_message_interval", dmarcStringConfigured(config.ForensicMessageInterval)},
	}
	dnsFields := []struct {
		name       string
		configured bool
	}{
		{"dns_dmarc_records", dmarcBoolConfigured(config.DNSDMARCRecords)},
		{"dns_dkim_records", dmarcBoolConfigured(config.DNSDKIMRecords)},
		{"dns_spf_records", dmarcBoolConfigured(config.DNSSPFRecords)},
	}
	if config.Type.ValueString() != "complianceMonitor" {
		for _, field := range complianceFields {
			if field.configured {
				diags.AddAttributeError(pathRoot(field.name), "Invalid notification trigger field", fmt.Sprintf("%s can only be configured when type is complianceMonitor.", field.name))
			}
		}
	}
	if config.Type.ValueString() != "dnsMonitor" {
		for _, field := range dnsFields {
			if field.configured {
				diags.AddAttributeError(pathRoot(field.name), "Invalid notification trigger field", fmt.Sprintf("%s can only be configured when type is dnsMonitor.", field.name))
			}
		}
	}
}

func dmarcStringConfigured(value types.String) bool { return !value.IsNull() && !value.IsUnknown() }
func dmarcBoolConfigured(value types.Bool) bool     { return !value.IsNull() && !value.IsUnknown() }
func dmarcInt64Configured(value types.Int64) bool   { return !value.IsNull() && !value.IsUnknown() }

func (r *dmarcNotificationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcNotificationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateManagedDMARCNotification(ctx, plan.Type.ValueString(), request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC notification", err.Error())
		return
	}
	if created.ID == "" {
		resp.Diagnostics.AddError("Unable to create DMARC notification", "Mimecast returned no notification ID.")
		return
	}
	created, err = r.client.GetManagedDMARCNotification(ctx, created.ID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC notification", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcNotificationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcNotificationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCNotification(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC notification", err.Error())
		return
	}
	state.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcNotificationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dmarcNotificationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateManagedDMARCNotification(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update DMARC notification", err.Error())
		return
	}
	updated, err := r.client.GetManagedDMARCNotification(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated DMARC notification", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcNotificationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcNotificationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCNotification(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC notification", err.Error())
	}
}

func (r *dmarcNotificationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (model dmarcNotificationResourceModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.DMARCNotificationRequest {
	emails, emailDiags := dmarcStringsFromSet(ctx, model.Emails)
	domains, domainDiags := dmarcOptionalStringSetPointer(ctx, model.DomainIDs)
	groups, groupDiags := dmarcOptionalStringSetPointer(ctx, model.GroupIDs)
	diags.Append(emailDiags...)
	diags.Append(domainDiags...)
	diags.Append(groupDiags...)
	request := client.DMARCNotificationRequest{Emails: emails, Frequency: model.Frequency.ValueString(), Domains: domains, Groups: groups}
	switch model.Type.ValueString() {
	case "complianceMonitor":
		if model.hasComplianceTriggerConfig() {
			request.TriggerConfig = &client.DMARCNotificationTriggerConfig{
				IsIndividualDomainAlert: boolPtr(model.IsIndividualDomainAlert),
				InvalidMessageTrigger:   dmarcComplianceTriggerFromModel(model.InvalidMessageEnabled, model.InvalidMessageThreshold, model.InvalidMessageInterval),
				DMARCComplianceTrigger:  dmarcComplianceTriggerFromModel(model.DMARCComplianceEnabled, model.DMARCComplianceThreshold, model.DMARCComplianceInterval),
				ForensicMessageTrigger:  dmarcComplianceTriggerFromModel(model.ForensicMessageEnabled, model.ForensicMessageThreshold, model.ForensicMessageInterval),
			}
		}
	case "dnsMonitor":
		if model.hasDNSTriggerConfig() {
			request.TriggerConfig = &client.DMARCNotificationTriggerConfig{
				DMARCRecords: boolPtr(model.DNSDMARCRecords),
				DKIMRecords:  boolPtr(model.DNSDKIMRecords),
				SPFRecords:   boolPtr(model.DNSSPFRecords),
			}
		}
	}
	return request
}

func dmarcComplianceTriggerFromModel(enabled types.Bool, threshold types.Int64, interval types.String) *client.DMARCComplianceTrigger {
	if !dmarcBoolConfigured(enabled) && !dmarcInt64Configured(threshold) && !dmarcStringConfigured(interval) {
		return nil
	}
	return &client.DMARCComplianceTrigger{Enabled: boolPtr(enabled), Threshold: dmarcInt64Pointer(threshold), Interval: interval.ValueString()}
}

func (model dmarcNotificationResourceModel) hasComplianceTriggerConfig() bool {
	return dmarcBoolConfigured(model.IsIndividualDomainAlert) ||
		dmarcComplianceTriggerFromModel(model.InvalidMessageEnabled, model.InvalidMessageThreshold, model.InvalidMessageInterval) != nil ||
		dmarcComplianceTriggerFromModel(model.DMARCComplianceEnabled, model.DMARCComplianceThreshold, model.DMARCComplianceInterval) != nil ||
		dmarcComplianceTriggerFromModel(model.ForensicMessageEnabled, model.ForensicMessageThreshold, model.ForensicMessageInterval) != nil
}

func (model dmarcNotificationResourceModel) hasDNSTriggerConfig() bool {
	return dmarcBoolConfigured(model.DNSDMARCRecords) || dmarcBoolConfigured(model.DNSDKIMRecords) || dmarcBoolConfigured(model.DNSSPFRecords)
}

func (model *dmarcNotificationResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCNotification, diags *diag.Diagnostics) {
	model.ID = stringValue(result.ID)
	model.Type = stringValue(result.Type)
	model.Frequency = stringValue(result.Frequency)
	model.NextTrigger = stringValue(result.NextTrigger)
	var setDiags diag.Diagnostics
	model.Emails, setDiags = setFromStrings(ctx, result.Emails)
	diags.Append(setDiags...)
	domainIDs := make([]string, 0, len(result.Domains))
	for _, domain := range result.Domains {
		if domain.ID != "" {
			domainIDs = append(domainIDs, domain.ID)
		}
	}
	groupIDs := make([]string, 0, len(result.Groups))
	for _, group := range result.Groups {
		if group.ID != "" {
			groupIDs = append(groupIDs, group.ID)
		}
	}
	model.DomainIDs, setDiags = setFromStrings(ctx, domainIDs)
	diags.Append(setDiags...)
	model.GroupIDs, setDiags = setFromStrings(ctx, groupIDs)
	diags.Append(setDiags...)
	model.clearTriggerConfig()
	if result.TriggerConfig == nil {
		return
	}
	config := result.TriggerConfig
	model.IsIndividualDomainAlert = boolValue(config.IsIndividualDomainAlert)
	dmarcComplianceTriggerToModel(config.InvalidMessageTrigger, &model.InvalidMessageEnabled, &model.InvalidMessageThreshold, &model.InvalidMessageInterval)
	dmarcComplianceTriggerToModel(config.DMARCComplianceTrigger, &model.DMARCComplianceEnabled, &model.DMARCComplianceThreshold, &model.DMARCComplianceInterval)
	dmarcComplianceTriggerToModel(config.ForensicMessageTrigger, &model.ForensicMessageEnabled, &model.ForensicMessageThreshold, &model.ForensicMessageInterval)
	model.DNSDMARCRecords = boolValue(config.DMARCRecords)
	model.DNSDKIMRecords = boolValue(config.DKIMRecords)
	model.DNSSPFRecords = boolValue(config.SPFRecords)
}

func (model *dmarcNotificationResourceModel) clearTriggerConfig() {
	model.IsIndividualDomainAlert = types.BoolNull()
	model.InvalidMessageEnabled = types.BoolNull()
	model.InvalidMessageThreshold = types.Int64Null()
	model.InvalidMessageInterval = types.StringNull()
	model.DMARCComplianceEnabled = types.BoolNull()
	model.DMARCComplianceThreshold = types.Int64Null()
	model.DMARCComplianceInterval = types.StringNull()
	model.ForensicMessageEnabled = types.BoolNull()
	model.ForensicMessageThreshold = types.Int64Null()
	model.ForensicMessageInterval = types.StringNull()
	model.DNSDMARCRecords = types.BoolNull()
	model.DNSDKIMRecords = types.BoolNull()
	model.DNSSPFRecords = types.BoolNull()
}

func dmarcComplianceTriggerToModel(trigger *client.DMARCComplianceTrigger, enabled *types.Bool, threshold *types.Int64, interval *types.String) {
	if trigger == nil {
		*enabled = types.BoolNull()
		*threshold = types.Int64Null()
		*interval = types.StringNull()
		return
	}
	*enabled = boolValue(trigger.Enabled)
	*threshold = dmarcInt64Value(trigger.Threshold)
	*interval = stringValue(trigger.Interval)
}

type dmarcEmailValidator struct{}

func (dmarcEmailValidator) Description(context.Context) string {
	return "must be a valid email address"
}
func (dmarcEmailValidator) MarkdownDescription(context.Context) string {
	return "must be a valid email address"
}
func (dmarcEmailValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !validDMARCEmail(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid email address", "Email address must use a valid mailbox format.")
	}
}

type dmarcEmailSetValidator struct{}

func (dmarcEmailSetValidator) Description(context.Context) string {
	return "must contain valid email addresses"
}
func (dmarcEmailSetValidator) MarkdownDescription(context.Context) string {
	return "must contain valid email addresses"
}
func (dmarcEmailSetValidator) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for _, element := range req.ConfigValue.Elements() {
		value, ok := element.(types.String)
		if !ok {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid email address set", "Email address set contains an unexpected value type.")
			return
		}
		if value.IsNull() || value.IsUnknown() {
			continue
		}
		if !validDMARCEmail(value.ValueString()) {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid email address", "Email address must use a valid mailbox format.")
			return
		}
	}
}

func validDMARCEmail(value string) bool {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value
}

// ---- DMARC policy preset --------------------------------------------------

type dmarcPolicyPresetResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	Name                    types.String `tfsdk:"name"`
	Description             types.String `tfsdk:"description"`
	IsDefaultPolicy         types.Bool   `tfsdk:"is_default_policy"`
	Version                 types.String `tfsdk:"version"`
	Policy                  types.String `tfsdk:"policy"`
	SubdomainPolicy         types.String `tfsdk:"subdomain_policy"`
	RUAAddresses            types.Set    `tfsdk:"rua_addresses"`
	RUFAddresses            types.Set    `tfsdk:"ruf_addresses"`
	DKIMAlignment           types.String `tfsdk:"dkim_alignment"`
	SPFAlignment            types.String `tfsdk:"spf_alignment"`
	ReportInterval          types.Int64  `tfsdk:"report_interval"`
	FailureReportingOptions types.String `tfsdk:"failure_reporting_options"`
	FailureReportFormat     types.String `tfsdk:"failure_report_format"`
	Percentage              types.Int64  `tfsdk:"percentage"`
}

type dmarcPolicyPresetResource struct{ client *client.Client }

// NewDMARCPolicyPresetResource manages a Mimecast DMARC Analyzer policy preset.
func NewDMARCPolicyPresetResource() resource.Resource { return &dmarcPolicyPresetResource{} }

func (r *dmarcPolicyPresetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_policy_preset"
}

func (r *dmarcPolicyPresetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast DMARC Analyzer DMARC policy preset.", Attributes: map[string]schema.Attribute{
		"id":                idAttr("DMARC Analyzer policy-preset ID."),
		"name":              schema.StringAttribute{Description: "Policy-preset name.", Required: true, Validators: []validator.String{stringvalidator.LengthAtMost(100)}},
		"description":       schema.StringAttribute{Description: "Policy-preset description.", Optional: true, Validators: []validator.String{stringvalidator.LengthAtMost(500)}},
		"is_default_policy": schema.BoolAttribute{Description: "Whether this is the account default policy preset.", Computed: true},
		"version":           requiredString("DMARC definition version, such as DMARC1."),
		"policy":            schema.StringAttribute{Description: "DMARC policy action.", Required: true, Validators: []validator.String{stringvalidator.OneOf("none", "quarantine", "reject")}},
		"subdomain_policy":  schema.StringAttribute{Description: "DMARC subdomain policy action.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("none", "quarantine", "reject")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"rua_addresses": schema.SetAttribute{
			Description: "Aggregate-report recipient addresses.", Optional: true, Computed: true, Sensitive: true, ElementType: types.StringType,
			PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"ruf_addresses": schema.SetAttribute{
			Description: "Forensic-report recipient addresses.", Optional: true, Computed: true, Sensitive: true, ElementType: types.StringType,
			PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"dkim_alignment":            schema.StringAttribute{Description: "DKIM alignment mode.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("r", "s")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"spf_alignment":             schema.StringAttribute{Description: "SPF alignment mode.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("r", "s")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"report_interval":           optionalComputedInt64("Aggregate report interval in seconds."),
		"failure_reporting_options": optionalComputedString("Colon-delimited DMARC failure reporting options."),
		"failure_report_format":     optionalComputedString("DMARC failure report format."),
		"percentage": schema.Int64Attribute{
			Description: "Percentage of messages to which the policy applies.", Optional: true, Computed: true,
			Validators: []validator.Int64{int64validator.Between(0, 100)},
		},
	}}
}

func (r *dmarcPolicyPresetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcPolicyPresetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcPolicyPresetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateManagedDMARCPolicyPreset(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC policy preset", err.Error())
		return
	}
	if created.ID == "" {
		resp.Diagnostics.AddError("Unable to create DMARC policy preset", "Mimecast returned no policy-preset ID.")
		return
	}
	created, err = r.client.GetManagedDMARCPolicyPreset(ctx, created.ID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC policy preset", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcPolicyPresetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcPolicyPresetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCPolicyPreset(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC policy preset", err.Error())
		return
	}
	state.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcPolicyPresetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dmarcPolicyPresetResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateManagedDMARCPolicyPreset(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update DMARC policy preset", err.Error())
		return
	}
	updated, err := r.client.GetManagedDMARCPolicyPreset(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated DMARC policy preset", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcPolicyPresetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcPolicyPresetResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCPolicyPreset(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC policy preset", err.Error())
	}
}

func (r *dmarcPolicyPresetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (model dmarcPolicyPresetResourceModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.DMARCPolicyPresetRequest {
	rua, ruaDiags := dmarcOptionalStringSetPointer(ctx, model.RUAAddresses)
	ruf, rufDiags := dmarcOptionalStringSetPointer(ctx, model.RUFAddresses)
	diags.Append(ruaDiags...)
	diags.Append(rufDiags...)
	return client.DMARCPolicyPresetRequest{
		Name:        model.Name.ValueString(),
		Description: model.Description.ValueString(),
		ManagedDMARCDefinition: client.ManagedDMARCDefinition{
			Version:                 model.Version.ValueString(),
			Policy:                  model.Policy.ValueString(),
			SubdomainPolicy:         model.SubdomainPolicy.ValueString(),
			RUAAddresses:            rua,
			RUFAddresses:            ruf,
			DKIMAlignment:           model.DKIMAlignment.ValueString(),
			SPFAlignment:            model.SPFAlignment.ValueString(),
			ReportInterval:          dmarcInt64Pointer(model.ReportInterval),
			FailureReportingOptions: model.FailureReportingOptions.ValueString(),
			FailureReportFormat:     model.FailureReportFormat.ValueString(),
			Percentage:              dmarcInt64Pointer(model.Percentage),
		},
	}
}

func (model *dmarcPolicyPresetResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCPolicyPreset, diags *diag.Diagnostics) {
	model.ID = stringValue(result.ID)
	model.Name = stringValue(result.Name)
	model.Description = stringValue(result.Description)
	model.IsDefaultPolicy = boolValue(result.IsDefaultPolicy)
	model.Version = stringValue(result.Version)
	model.Policy = stringValue(result.Policy)
	model.SubdomainPolicy = stringValue(result.SubdomainPolicy)
	model.DKIMAlignment = stringValue(result.DKIMAlignment)
	model.SPFAlignment = stringValue(result.SPFAlignment)
	model.ReportInterval = dmarcInt64Value(result.ReportInterval)
	model.FailureReportingOptions = stringValue(result.FailureReportingOptions)
	model.FailureReportFormat = stringValue(result.FailureReportFormat)
	model.Percentage = dmarcInt64Value(result.Percentage)
	var setDiags diag.Diagnostics
	model.RUAAddresses, setDiags = dmarcSetFromPointer(ctx, result.RUAAddresses)
	diags.Append(setDiags...)
	model.RUFAddresses, setDiags = dmarcSetFromPointer(ctx, result.RUFAddresses)
	diags.Append(setDiags...)
}

var (
	_ resource.Resource                   = (*dmarcManagedDomainResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcManagedDomainResource)(nil)
	_ resource.Resource                   = (*dmarcDomainGroupResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcDomainGroupResource)(nil)
	_ resource.Resource                   = (*dmarcNotificationResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcNotificationResource)(nil)
	_ resource.ResourceWithValidateConfig = (*dmarcNotificationResource)(nil)
	_ resource.Resource                   = (*dmarcPolicyPresetResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcPolicyPresetResource)(nil)
)
