package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type policyModel struct {
	ID            types.String `tfsdk:"id"`
	Description   types.String `tfsdk:"description"`
	Option        types.String `tfsdk:"option"`
	DefinitionID  types.String `tfsdk:"definition_id"`
	FromPart      types.String `tfsdk:"from_part"`
	FromType      types.String `tfsdk:"from_type"`
	FromGroupID   types.String `tfsdk:"from_group_id"`
	FromDomain    types.String `tfsdk:"from_domain"`
	FromEmail     types.String `tfsdk:"from_email_address"`
	FromAttrID    types.String `tfsdk:"from_attribute_id"`
	FromAttrValue types.String `tfsdk:"from_attribute_value"`
	ToType        types.String `tfsdk:"to_type"`
	ToGroupID     types.String `tfsdk:"to_group_id"`
	ToDomain      types.String `tfsdk:"to_domain"`
	ToEmail       types.String `tfsdk:"to_email_address"`
	ToAttrID      types.String `tfsdk:"to_attribute_id"`
	ToAttrValue   types.String `tfsdk:"to_attribute_value"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	Enforced      types.Bool   `tfsdk:"enforced"`
	Override      types.Bool   `tfsdk:"override"`
	Bidirectional types.Bool   `tfsdk:"bidirectional"`
	FromEternal   types.Bool   `tfsdk:"from_eternal"`
	ToEternal     types.Bool   `tfsdk:"to_eternal"`
	FromDateTime  types.String `tfsdk:"from_date_time"`
	ToDateTime    types.String `tfsdk:"to_date_time"`
	SourceIPs     types.List   `tfsdk:"source_ips"`
	Hostnames     types.List   `tfsdk:"hostnames"`
	SPFDomains    types.List   `tfsdk:"spf_domains"`
}

type policyResource struct {
	kind        string
	typeName    string
	description string
	client      *client.Client
}

func newPolicyResource(kind, typeName, description string) resource.Resource {
	return &policyResource{kind: kind, typeName: typeName, description: description}
}

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.typeName
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"id":                   idAttr("Mimecast policy ID."),
		"description":          requiredString("Policy description."),
		"option":               optionalString("Policy action option. Valid values depend on the policy type."),
		"definition_id":        optionalString("Definition ID referenced by this policy, when the policy type requires a definition."),
		"from_part":            optionalString("Which sender part the policy applies to, such as `envelope_from`, `header_from`, or `both`."),
		"from_type":            requiredString("Source target type, such as `everyone`, `internal_addresses`, `external_addresses`, `email_domain`, `profile_group`, `address_attribute_value`, or `individual_email_address`."),
		"from_group_id":        optionalString("Source profile group ID when `from_type` is `profile_group`."),
		"from_domain":          optionalString("Source domain when `from_type` is `email_domain`."),
		"from_email_address":   optionalString("Source email address when `from_type` is `individual_email_address`."),
		"from_attribute_id":    optionalString("Source address attribute ID when `from_type` is `address_attribute_value`."),
		"from_attribute_value": optionalString("Source address attribute value when `from_type` is `address_attribute_value`."),
		"to_type":              requiredString("Destination target type."),
		"to_group_id":          optionalString("Destination profile group ID when `to_type` is `profile_group`."),
		"to_domain":            optionalString("Destination domain when `to_type` is `email_domain`."),
		"to_email_address":     optionalString("Destination email address when `to_type` is `individual_email_address`."),
		"to_attribute_id":      optionalString("Destination address attribute ID when `to_type` is `address_attribute_value`."),
		"to_attribute_value":   optionalString("Destination address attribute value when `to_type` is `address_attribute_value`."),
		"enabled":              optionalComputedBool("Whether the policy is enabled. Defaults are applied by Mimecast when omitted."),
		"enforced":             optionalComputedBool("Whether policy enforcement is enabled, when supported by the policy type."),
		"override":             optionalComputedBool("Whether this policy overrides lower-priority matches, when supported by the policy type."),
		"bidirectional":        optionalComputedBool("Whether the policy applies in both directions."),
		"from_eternal":         optionalComputedBool("Whether the source side schedule is eternal."),
		"to_eternal":           optionalComputedBool("Whether the destination side schedule is eternal."),
		"from_date_time":       optionalComputedString("Optional source schedule start/end value accepted by Mimecast."),
		"to_date_time":         optionalComputedString("Optional destination schedule start/end value accepted by Mimecast."),
		"source_ips":           optionalComputedStringList("Source IP ranges in CIDR notation, when supported by the policy type."),
		"hostnames":            optionalComputedStringList("Hostnames condition, when supported by anti-spoofing policies."),
		"spf_domains":          optionalComputedStringList("SPF domains condition, when supported by anti-spoofing bypass policies."),
	}
	resp.Schema = schema.Schema{Description: r.description, Attributes: attrs}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = configureClient(req.ProviderData, resp)
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := plan.toAPI(ctx, &resp.Diagnostics)
	validatePolicyModel(r.kind, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreatePolicy(ctx, r.kind, p)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Mimecast policy", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetPolicy(ctx, r.kind, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Mimecast policy", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.GetPolicy(ctx, r.kind, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Mimecast policy", err.Error())
		return
	}
	state.fromAPI(ctx, p, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := plan.toAPI(ctx, &resp.Diagnostics)
	validatePolicyModel(r.kind, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdatePolicy(ctx, r.kind, plan.ID.ValueString(), p); err != nil {
		resp.Diagnostics.AddError("Unable to update Mimecast policy", err.Error())
		return
	}
	updated, err := r.client.GetPolicy(ctx, r.kind, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Mimecast policy", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeletePolicy(ctx, r.kind, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Mimecast policy", err.Error())
	}
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m policyModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.Policy {
	sourceIPs, d := stringsFromList(ctx, m.SourceIPs)
	diags.Append(d...)
	hostnames, d := stringsFromList(ctx, m.Hostnames)
	diags.Append(d...)
	spfDomains, d := stringsFromList(ctx, m.SPFDomains)
	diags.Append(d...)
	return client.Policy{
		ID: m.ID.ValueString(), Description: m.Description.ValueString(), Option: m.Option.ValueString(), DefinitionID: m.DefinitionID.ValueString(),
		FromPart: m.FromPart.ValueString(), From: targetFrom(m.FromType, m.FromGroupID, m.FromDomain, m.FromEmail, m.FromAttrID, m.FromAttrValue),
		To:      targetFrom(m.ToType, m.ToGroupID, m.ToDomain, m.ToEmail, m.ToAttrID, m.ToAttrValue),
		Enabled: boolPtr(m.Enabled), Enforced: boolPtr(m.Enforced), Override: boolPtr(m.Override), Bidirectional: boolPtr(m.Bidirectional),
		FromEternal: boolPtr(m.FromEternal), ToEternal: boolPtr(m.ToEternal), FromDateTime: m.FromDateTime.ValueString(), ToDateTime: m.ToDateTime.ValueString(),
		SourceIPs: sourceIPs, Hostnames: hostnames, SPFDomains: spfDomains,
	}
}

func targetFrom(t, groupID, domain, email, attrID, attrValue types.String) client.PolicyTarget {
	out := client.PolicyTarget{Type: t.ValueString(), GroupID: groupID.ValueString(), Domain: domain.ValueString(), EmailAddress: email.ValueString()}
	if attrID.ValueString() != "" || attrValue.ValueString() != "" {
		out.Attribute = &client.TargetAttribute{ID: attrID.ValueString(), Value: attrValue.ValueString()}
	}
	return out
}

func (m *policyModel) fromAPI(ctx context.Context, p client.Policy, diags *diag.Diagnostics) {
	if p.ID != "" {
		m.ID = stringValue(p.ID)
	}
	m.Description = stringValue(p.Description)
	m.Option = stringValue(p.Option)
	m.DefinitionID = stringValue(p.DefinitionID)
	m.FromPart = stringValue(p.FromPart)
	setTarget(&m.FromType, &m.FromGroupID, &m.FromDomain, &m.FromEmail, &m.FromAttrID, &m.FromAttrValue, p.From)
	setTarget(&m.ToType, &m.ToGroupID, &m.ToDomain, &m.ToEmail, &m.ToAttrID, &m.ToAttrValue, p.To)
	m.Enabled = boolValue(p.Enabled)
	m.Enforced = boolValue(p.Enforced)
	m.Override = boolValue(p.Override)
	m.Bidirectional = boolValue(p.Bidirectional)
	m.FromEternal = boolValue(p.FromEternal)
	m.ToEternal = boolValue(p.ToEternal)
	m.FromDateTime = stringValue(firstNonEmpty(p.FromDateTime, p.FromDate))
	m.ToDateTime = stringValue(firstNonEmpty(p.ToDateTime, p.ToDate))
	var d diag.Diagnostics
	m.SourceIPs, d = listFromStrings(ctx, p.SourceIPs)
	diags.Append(d...)
	m.Hostnames, d = listFromStrings(ctx, p.Hostnames)
	diags.Append(d...)
	m.SPFDomains, d = listFromStrings(ctx, p.SPFDomains)
	diags.Append(d...)
}

func setTarget(t, groupID, domain, email, attrID, attrValue *types.String, in client.PolicyTarget) {
	*t = stringValue(in.Type)
	*groupID = stringValue(in.ResolvedGroupID())
	*domain = stringValue(in.Domain)
	*email = stringValue(in.EmailAddress)
	if in.Attribute != nil {
		*attrID = stringValue(in.Attribute.ID)
		*attrValue = stringValue(in.Attribute.Value)
	}
}

func validatePolicyModel(kind string, model policyModel, diags *diag.Diagnostics) {
	validateTarget := func(side string, targetType, groupID, domain, email, attrID, attrValue types.String) {
		valid := map[string]bool{
			"everyone": true, "internal_addresses": true, "external_addresses": true,
			"email_domain": true, "profile_group": true, "address_attribute_value": true,
			"individual_email_address": true,
		}
		value := targetType.ValueString()
		if !valid[value] {
			diags.AddError("Invalid "+side+" target", side+"_type is not a supported Mimecast policy target type.")
			return
		}
		required := ""
		switch value {
		case "profile_group":
			required = groupID.ValueString()
		case "email_domain":
			required = domain.ValueString()
		case "individual_email_address":
			required = email.ValueString()
		case "address_attribute_value":
			if attrID.ValueString() != "" && attrValue.ValueString() != "" {
				required = "set"
			}
		default:
			required = "set"
		}
		if required == "" {
			diags.AddError("Incomplete "+side+" target", "Set the attribute required by "+side+"_type.")
		}
	}
	validateTarget("from", model.FromType, model.FromGroupID, model.FromDomain, model.FromEmail, model.FromAttrID, model.FromAttrValue)
	validateTarget("to", model.ToType, model.ToGroupID, model.ToDomain, model.ToEmail, model.ToAttrID, model.ToAttrValue)
	if (kind == "delivery_route" || kind == "dns_authentication_outbound") && model.DefinitionID.ValueString() == "" {
		diags.AddError("Missing policy definition", "definition_id is required for this policy family.")
	}
	if kind != "anti_spoofing" && !model.Hostnames.IsNull() {
		diags.AddError("Unsupported policy attribute", "hostnames is only supported by anti-spoofing policies.")
	}
	if kind != "anti_spoofing_bypass" && !model.SPFDomains.IsNull() {
		diags.AddError("Unsupported policy attribute", "spf_domains is only supported by anti-spoofing bypass policies.")
	}
}

func NewGreylistingPolicyResource() resource.Resource {
	return newPolicyResource("greylisting", "greylisting_policy", "Manage a Mimecast Cloud Gateway greylisting policy.")
}
func NewDeliveryRoutePolicyResource() resource.Resource {
	return newPolicyResource("delivery_route", "delivery_route_policy", "Manage a Mimecast Cloud Gateway delivery route policy.")
}
func NewAntiSpoofingPolicyResource() resource.Resource {
	return newPolicyResource("anti_spoofing", "anti_spoofing_policy", "Manage a Mimecast Cloud Gateway anti-spoofing policy.")
}
func NewAntiSpoofingBypassPolicyResource() resource.Resource {
	return newPolicyResource("anti_spoofing_bypass", "anti_spoofing_bypass_policy", "Manage a Mimecast Cloud Gateway anti-spoofing bypass policy.")
}
func NewBlockedSenderPolicyResource() resource.Resource {
	return newPolicyResource("blocked_sender", "blocked_sender_policy", "Manage a Mimecast Cloud Gateway blocked sender policy.")
}
func NewDNSAuthenticationOutboundPolicyResource() resource.Resource {
	return newPolicyResource("dns_authentication_outbound", "dns_authentication_outbound_policy", "Manage a Mimecast DNS authentication outbound policy.")
}
