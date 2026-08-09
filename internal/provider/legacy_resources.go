package provider

import (
	"context"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

var (
	addressAlterationTypes  = []string{"all", "envelope_from", "envelope_to", "from", "reply_to", "to_cc_bcc", "sender"}
	addressAlterationRoutes = []string{"all", "inbound", "outbound"}
	legacyPolicyTargetTypes = []string{"everyone", "internal_addresses", "external_addresses", "email_domain", "profile_group", "address_attribute_value", "individual_email_address"}
	webPolicyTargetTypes    = []string{"everyone", "internal_addresses", "external_addresses", "email_domain", "profile_group", "address_attribute_value", "individual_email_address", "free_mail_domains", "header_display_name", "web_device_group", "web_device"}
)

// addressAlterationSetsModel is deliberately flat. The legacy response is a
// recursive folder tree, which the client flattens and sorts by stable ID.
type addressAlterationSetsModel struct {
	ID       types.String                `tfsdk:"id"`
	FolderID types.String                `tfsdk:"folder_id"`
	Depth    types.Int64                 `tfsdk:"depth"`
	Items    []addressAlterationSetModel `tfsdk:"items"`
}

type addressAlterationSetModel struct {
	ID          types.String `tfsdk:"id"`
	Description types.String `tfsdk:"description"`
	ParentID    types.String `tfsdk:"parent_id"`
	Source      types.String `tfsdk:"source"`
	FolderCount types.Int64  `tfsdk:"folder_count"`
	UserCount   types.Int64  `tfsdk:"user_count"`
}

// NewAddressAlterationSetsDataSource reads typed Address Alteration Set
// inventory. No resource is provided because the official API has no safe
// delete lifecycle for sets.
func NewAddressAlterationSetsDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id":        dsID("Stable Address Alteration Set inventory ID."),
		"folder_id": dsschema.StringAttribute{Description: "Optional set ID to scope the read.", Optional: true},
		"depth":     dsschema.Int64Attribute{Description: "Folder recursion depth requested from Mimecast. Defaults to 1.", Optional: true, Computed: true, Validators: []validator.Int64{positiveInt64Validator{}}},
		"items": dsItems(map[string]dsschema.Attribute{
			"id": dsID("Address Alteration Set ID."), "description": dsString("Set description."),
			"parent_id": dsString("Parent set ID."), "source": dsString("Set source, such as cloud or ldap."),
			"folder_count": dsInt64("Number of child sets."), "user_count": dsInt64("Number of users in the set."),
		}),
	}
	return newTypedDataSource("address_alteration_sets", "Read Address Alteration Sets through the legacy POST-style read endpoint. Mutation is excluded because the API has no safe delete lifecycle.", attrs, func(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		var state addressAlterationSetsModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		depth := state.Depth.ValueInt64()
		if state.Depth.IsNull() || state.Depth.IsUnknown() || depth <= 0 {
			depth = 1
		}
		items, err := c.ListAddressAlterationSets(ctx, state.FolderID.ValueString(), depth)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Address Alteration Sets", err.Error())
			return
		}
		state.Depth = types.Int64Value(depth)
		state.ID = types.StringValue("address_alteration_sets")
		if state.FolderID.ValueString() != "" {
			state.ID = types.StringValue(normalizeCompositeID("address_alteration_sets", state.FolderID.ValueString()))
		}
		state.Items = make([]addressAlterationSetModel, 0, len(items))
		for _, item := range items {
			state.Items = append(state.Items, addressAlterationSetModel{
				ID: stringValue(item.ID), Description: stringValue(item.Description), ParentID: stringValue(item.ParentID),
				Source: stringValue(item.Source), FolderCount: types.Int64Value(item.FolderCount), UserCount: types.Int64Value(item.UserCount),
			})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	})
}

type addressAlterationDefinitionModel struct {
	ID              types.String `tfsdk:"id"`
	FolderID        types.String `tfsdk:"folder_id"`
	AddressType     types.String `tfsdk:"address_type"`
	OriginalAddress types.String `tfsdk:"original_address"`
	NewAddress      types.String `tfsdk:"new_address"`
	Routing         types.String `tfsdk:"routing"`
}

type addressAlterationDefinitionResource struct{ client *client.Client }

func NewAddressAlterationDefinitionResource() resource.Resource {
	return &addressAlterationDefinitionResource{}
}

func (r *addressAlterationDefinitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_address_alteration_definition"
}

func (r *addressAlterationDefinitionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{Description: "Manage one immutable Mimecast Address Alteration definition.", Attributes: map[string]schema.Attribute{
		"id":               idAttr("Mimecast Address Alteration definition ID."),
		"folder_id":        schema.StringAttribute{Description: "Optional Address Alteration Set ID. Root-level definitions omit this value.", Optional: true, PlanModifiers: replace},
		"address_type":     schema.StringAttribute{Description: "Address component to alter.", Required: true, Validators: []validator.String{stringvalidator.OneOf(addressAlterationTypes...)}, PlanModifiers: replace},
		"original_address": schema.StringAttribute{Description: "Original address pattern to rewrite.", Required: true, PlanModifiers: replace},
		"new_address":      schema.StringAttribute{Description: "Replacement address pattern.", Required: true, PlanModifiers: replace},
		"routing":          schema.StringAttribute{Description: "Mail route to which the rewrite applies.", Required: true, Validators: []validator.String{stringvalidator.OneOf(addressAlterationRoutes...)}, PlanModifiers: replace},
	}}
}

func (r *addressAlterationDefinitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *addressAlterationDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan addressAlterationDefinitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateAddressAlterationDefinition(ctx, plan.toAPI())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Address Alteration definition", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetAddressAlterationDefinition(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Address Alteration definition", err.Error())
		return
	}
	plan.fromAPI(created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *addressAlterationDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state addressAlterationDefinitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	definition, err := r.client.GetAddressAlterationDefinition(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Address Alteration definition", err.Error())
		return
	}
	state.fromAPI(definition)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *addressAlterationDefinitionResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Address Alteration definition cannot be updated", "All definition attributes require replacement under the Mimecast API contract.")
}

func (r *addressAlterationDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state addressAlterationDefinitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteAddressAlterationDefinition(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Address Alteration definition", err.Error())
	}
}

func (r *addressAlterationDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m addressAlterationDefinitionModel) toAPI() client.AddressAlterationDefinition {
	return client.AddressAlterationDefinition{ID: m.ID.ValueString(), FolderID: m.FolderID.ValueString(), AddressType: m.AddressType.ValueString(), OriginalAddress: m.OriginalAddress.ValueString(), NewAddress: m.NewAddress.ValueString(), Routing: m.Routing.ValueString()}
}

func (m *addressAlterationDefinitionModel) fromAPI(in client.AddressAlterationDefinition) {
	if in.ID != "" {
		m.ID = types.StringValue(in.ID)
	}
	// The get-definition response omits folderId. Preserve configured state.
	if in.FolderID != "" {
		m.FolderID = stringValue(in.FolderID)
	}
	m.AddressType = stringValue(in.AddressType)
	m.OriginalAddress = stringValue(in.OriginalAddress)
	m.NewAddress = stringValue(in.NewAddress)
	m.Routing = stringValue(in.Routing)
}

type addressAlterationDefinitionsModel struct {
	ID    types.String                       `tfsdk:"id"`
	Items []addressAlterationDefinitionModel `tfsdk:"items"`
}

// NewAddressAlterationDefinitionsDataSource exposes definition IDs and their
// containing sets so an existing estate can be imported without manual ID
// discovery in the administration console.
func NewAddressAlterationDefinitionsDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable Address Alteration definition inventory ID."),
		"items": dsItems(map[string]dsschema.Attribute{
			"id": dsID("Address Alteration definition ID."), "folder_id": dsID("Containing Address Alteration Set ID."),
			"address_type": dsString("Address component altered by the definition."), "original_address": dsSensitiveString("Original address pattern."),
			"new_address": dsSensitiveString("Replacement address pattern."), "routing": dsString("Mail route to which the definition applies."),
		}),
	}
	return newTypedDataSource("address_alteration_definitions", "Read all Address Alteration definitions through the legacy filtered read contract with deterministic ordering.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListAddressAlterationDefinitions(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Address Alteration definitions", err.Error())
			return
		}
		items := make([]addressAlterationDefinitionModel, 0, len(out))
		for _, item := range out {
			model := addressAlterationDefinitionModel{}
			model.fromAPI(item)
			items = append(items, model)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &addressAlterationDefinitionsModel{ID: types.StringValue("address_alteration_definitions"), Items: items})...)
	})
}

type legacyPolicyTargetModel struct {
	Type           types.String `tfsdk:"type"`
	GroupID        types.String `tfsdk:"group_id"`
	EmailDomain    types.String `tfsdk:"email_domain"`
	EmailAddress   types.String `tfsdk:"email_address"`
	AttributeID    types.String `tfsdk:"attribute_id"`
	AttributeName  types.String `tfsdk:"attribute_name"`
	AttributeValue types.String `tfsdk:"attribute_value"`
}

type legacyPolicyModel struct {
	Description   types.String            `tfsdk:"description"`
	Comment       types.String            `tfsdk:"comment"`
	Enabled       types.Bool              `tfsdk:"enabled"`
	Enforced      types.Bool              `tfsdk:"enforced"`
	Override      types.Bool              `tfsdk:"override"`
	Bidirectional types.Bool              `tfsdk:"bidirectional"`
	From          legacyPolicyTargetModel `tfsdk:"from"`
	To            legacyPolicyTargetModel `tfsdk:"to"`
	FromPart      types.String            `tfsdk:"from_part"`
	FromDate      types.String            `tfsdk:"from_date"`
	FromEternal   types.Bool              `tfsdk:"from_eternal"`
	ToDate        types.String            `tfsdk:"to_date"`
	ToEternal     types.Bool              `tfsdk:"to_eternal"`
	SourceIPs     types.Set               `tfsdk:"source_ips"`
	Hostnames     types.Set               `tfsdk:"hostnames"`
	SPFDomains    types.Set               `tfsdk:"spf_domains"`
	CreateTime    types.String            `tfsdk:"create_time"`
	LastUpdated   types.String            `tfsdk:"last_updated"`
}

func legacyTargetSchema(web bool) schema.SingleNestedAttribute {
	typesAllowed := legacyPolicyTargetTypes
	if web {
		typesAllowed = webPolicyTargetTypes
	}
	return schema.SingleNestedAttribute{Required: true, Attributes: map[string]schema.Attribute{
		"type":            schema.StringAttribute{Description: "Mimecast policy target type.", Required: true, Validators: []validator.String{stringvalidator.OneOf(typesAllowed...)}},
		"group_id":        optionalString("Profile group ID when type is profile_group."),
		"email_domain":    optionalString("Email domain when type is email_domain."),
		"email_address":   optionalString("Email address when type is individual_email_address."),
		"attribute_id":    optionalString("Address attribute ID when type is address_attribute_value."),
		"attribute_name":  optionalString("Address attribute name when type is address_attribute_value."),
		"attribute_value": optionalString("Address attribute value when type is address_attribute_value."),
	}}
}

func legacyPolicySchema(web bool) schema.SingleNestedAttribute {
	attributes := map[string]schema.Attribute{
		"description":   requiredString("Policy description."),
		"comment":       optionalString("Policy comment."),
		"enabled":       optionalComputedBool("Whether the policy is enabled."),
		"enforced":      optionalComputedBool("Whether the policy is enforced."),
		"override":      optionalComputedBool("Whether the policy is evaluated before lower-priority matches."),
		"bidirectional": optionalComputedBool("Whether the policy applies in both mail-flow directions."),
		"from":          legacyTargetSchema(web), "to": legacyTargetSchema(web),
		"from_part":    schema.StringAttribute{Description: "Sender address part used for matching.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("envelope_from", "header_from", "both")}},
		"from_date":    optionalString("Policy start time in Mimecast ISO 8601 format."),
		"from_eternal": optionalComputedBool("Whether the policy has no scheduled start."),
		"to_date":      optionalString("Policy end time in Mimecast ISO 8601 format."),
		"to_eternal":   optionalComputedBool("Whether the policy has no scheduled end."),
		"source_ips":   schema.SetAttribute{Description: "Source IP ranges in CIDR notation.", Optional: true, Computed: true, ElementType: types.StringType},
		"create_time":  computedString("Policy creation time returned by Mimecast."),
		"last_updated": computedString("Most recent policy update time returned by Mimecast."),
	}
	attributes["hostnames"] = schema.SetAttribute{Description: "Source hostnames used as policy conditions. Supported by Web Security target policies.", Optional: true, Computed: true, ElementType: types.StringType}
	attributes["spf_domains"] = schema.SetAttribute{Description: "SPF domains used as policy conditions. Supported by Web Security target policies.", Optional: true, Computed: true, ElementType: types.StringType}
	return schema.SingleNestedAttribute{Required: true, Attributes: attributes}
}

func (m legacyPolicyTargetModel) toAPI() client.LegacyPolicyTarget {
	out := client.LegacyPolicyTarget{Type: m.Type.ValueString(), GroupID: m.GroupID.ValueString(), EmailDomain: m.EmailDomain.ValueString(), EmailAddress: m.EmailAddress.ValueString()}
	if m.AttributeID.ValueString() != "" || m.AttributeName.ValueString() != "" || m.AttributeValue.ValueString() != "" {
		out.Attribute = &client.LegacyPolicyAttribute{ID: m.AttributeID.ValueString(), Name: m.AttributeName.ValueString(), Value: m.AttributeValue.ValueString()}
	}
	return out
}

func (m *legacyPolicyTargetModel) fromAPI(in client.LegacyPolicyTarget) {
	m.Type = stringValue(in.Type)
	m.GroupID = stringValue(in.ResolvedGroupID())
	m.EmailDomain = stringValue(in.EmailDomain)
	m.EmailAddress = stringValue(in.EmailAddress)
	if in.Attribute != nil {
		m.AttributeID = stringValue(in.Attribute.ID)
		m.AttributeName = stringValue(in.Attribute.Name)
		m.AttributeValue = stringValue(in.Attribute.Value)
	} else {
		m.AttributeID = types.StringNull()
		m.AttributeName = types.StringNull()
		m.AttributeValue = types.StringNull()
	}
}

func (m legacyPolicyTargetModel) validate(side string, diags *diag.Diagnostics) {
	missing := false
	switch m.Type.ValueString() {
	case "profile_group":
		missing = m.GroupID.ValueString() == ""
	case "email_domain":
		missing = m.EmailDomain.ValueString() == ""
	case "individual_email_address":
		missing = m.EmailAddress.ValueString() == ""
	case "address_attribute_value":
		missing = m.AttributeID.ValueString() == "" || m.AttributeValue.ValueString() == ""
	}
	if missing {
		diags.AddError("Incomplete "+side+" target", "Set the value required by the selected "+side+" target type.")
	}
}

func (m legacyPolicyModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.LegacyPolicyScope {
	sourceIPs, d := stringsFromSet(ctx, m.SourceIPs)
	diags.Append(d...)
	hostnames, d := stringsFromSet(ctx, m.Hostnames)
	diags.Append(d...)
	spfDomains, d := stringsFromSet(ctx, m.SPFDomains)
	diags.Append(d...)
	conditions := &client.LegacyPolicyConditions{SourceIPs: sourceIPs, Hostnames: hostnames, SPFDomains: spfDomains}
	if len(sourceIPs) == 0 && len(hostnames) == 0 && len(spfDomains) == 0 {
		conditions = nil
	}
	return client.LegacyPolicyScope{
		Description: m.Description.ValueString(), Comment: m.Comment.ValueString(), Enabled: boolPtr(m.Enabled), Enforced: boolPtr(m.Enforced),
		Override: boolPtr(m.Override), Bidirectional: boolPtr(m.Bidirectional), From: m.From.toAPI(), To: m.To.toAPI(), FromPart: m.FromPart.ValueString(),
		FromDate: m.FromDate.ValueString(), FromEternal: boolPtr(m.FromEternal), ToDate: m.ToDate.ValueString(), ToEternal: boolPtr(m.ToEternal), Conditions: conditions,
	}
}

func (m *legacyPolicyModel) fromAPI(ctx context.Context, in client.LegacyPolicyScope, diags *diag.Diagnostics) {
	m.Description = stringValue(in.Description)
	// Some Address Alteration reads omit comment. Preserve planned/state value.
	if in.Comment != "" {
		m.Comment = stringValue(in.Comment)
	}
	m.Enabled = boolValue(in.Enabled)
	m.Enforced = boolValue(in.Enforced)
	m.Override = boolValue(in.Override)
	m.Bidirectional = boolValue(in.Bidirectional)
	m.From.fromAPI(in.From)
	m.To.fromAPI(in.To)
	m.FromPart = stringValue(in.FromPart)
	m.FromDate = stringValue(in.FromDate)
	m.FromEternal = boolValue(in.FromEternal)
	m.ToDate = stringValue(in.ToDate)
	m.ToEternal = boolValue(in.ToEternal)
	m.CreateTime = stringValue(in.CreateTime)
	m.LastUpdated = stringValue(in.LastUpdated)
	var sourceIPs, hostnames, spfDomains []string
	if in.Conditions != nil {
		sourceIPs = in.Conditions.SourceIPs
		hostnames = in.Conditions.Hostnames
		spfDomains = in.Conditions.SPFDomains
	}
	var d diag.Diagnostics
	m.SourceIPs, d = setFromStrings(ctx, sourceIPs)
	diags.Append(d...)
	m.Hostnames, d = setFromStrings(ctx, hostnames)
	diags.Append(d...)
	m.SPFDomains, d = setFromStrings(ctx, spfDomains)
	diags.Append(d...)
}

func (m legacyPolicyModel) validate(web bool, diags *diag.Diagnostics) {
	m.From.validate("from", diags)
	m.To.validate("to", diags)
	if !web {
		if !m.Hostnames.IsNull() && !m.Hostnames.IsUnknown() && len(m.Hostnames.Elements()) > 0 {
			diags.AddError("Unsupported Address Alteration condition", "hostnames is supported by Web Security target policies, not Address Alteration policies.")
		}
		if !m.SPFDomains.IsNull() && !m.SPFDomains.IsUnknown() && len(m.SPFDomains.Elements()) > 0 {
			diags.AddError("Unsupported Address Alteration condition", "spf_domains is supported by Web Security target policies, not Address Alteration policies.")
		}
	}
	if m.FromDate.ValueString() != "" && boolPtr(m.FromEternal) != nil && m.FromEternal.ValueBool() {
		diags.AddError("Conflicting policy schedule", "from_date cannot be combined with from_eternal = true.")
	}
	if m.ToDate.ValueString() != "" && boolPtr(m.ToEternal) != nil && m.ToEternal.ValueBool() {
		diags.AddError("Conflicting policy schedule", "to_date cannot be combined with to_eternal = true.")
	}
}

type addressAlterationPolicyModel struct {
	ID                     types.String       `tfsdk:"id"`
	AddressAlterationSetID types.String       `tfsdk:"address_alteration_set_id"`
	Policy                 *legacyPolicyModel `tfsdk:"policy"`
}

type addressAlterationPoliciesModel struct {
	ID    types.String                   `tfsdk:"id"`
	Items []addressAlterationPolicyModel `tfsdk:"items"`
}

func legacyPolicyTargetDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"type": dsString("Mimecast policy target type."), "group_id": dsID("Profile group ID."), "email_domain": dsString("Target email domain."),
		"email_address": dsSensitiveString("Target email address."), "attribute_id": dsID("Address attribute ID."), "attribute_name": dsString("Address attribute name."),
		"attribute_value": dsSensitiveString("Address attribute value."),
	}}
}

func legacyPolicyDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"description": dsString("Policy description."), "comment": dsString("Policy comment."), "enabled": dsBool("Whether enabled."), "enforced": dsBool("Whether enforced."),
		"override": dsBool("Whether lower-priority matches are overridden."), "bidirectional": dsBool("Whether applied in both directions."),
		"from": legacyPolicyTargetDataSourceAttribute(), "to": legacyPolicyTargetDataSourceAttribute(), "from_part": dsString("Sender address part used for matching."),
		"from_date": dsString("Policy start time."), "from_eternal": dsBool("Whether there is no scheduled start."), "to_date": dsString("Policy end time."),
		"to_eternal": dsBool("Whether there is no scheduled end."), "source_ips": dsschema.SetAttribute{Computed: true, ElementType: types.StringType},
		"hostnames": dsschema.SetAttribute{Computed: true, ElementType: types.StringType}, "spf_domains": dsschema.SetAttribute{Computed: true, ElementType: types.StringType},
		"create_time": dsString("Creation timestamp."), "last_updated": dsString("Last update timestamp."),
	}}
}

// NewAddressAlterationPoliciesDataSource uses the endpoint's documented
// omitted-ID behaviour to provide complete import discovery.
func NewAddressAlterationPoliciesDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable Address Alteration policy inventory ID."),
		"items": dsItems(map[string]dsschema.Attribute{
			"id": dsID("Address Alteration policy ID."), "address_alteration_set_id": dsID("Referenced Address Alteration Set ID."), "policy": legacyPolicyDataSourceAttribute(),
		}),
	}
	return newTypedDataSource("address_alteration_policies", "Read all Address Alteration policies through the documented omitted-ID legacy read contract.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListAddressAlterationPolicies(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Address Alteration policies", err.Error())
			return
		}
		items := make([]addressAlterationPolicyModel, 0, len(out))
		for _, item := range out {
			model := addressAlterationPolicyModel{}
			model.fromAPI(ctx, item, &resp.Diagnostics)
			items = append(items, model)
		}
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &addressAlterationPoliciesModel{ID: types.StringValue("address_alteration_policies"), Items: items})...)
	})
}

type addressAlterationPolicyResource struct{ client *client.Client }

func NewAddressAlterationPolicyResource() resource.Resource {
	return &addressAlterationPolicyResource{}
}

func (r *addressAlterationPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_address_alteration_policy"
}

func (r *addressAlterationPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast Address Alteration policy.", Attributes: map[string]schema.Attribute{
		"id":                        idAttr("Mimecast Address Alteration policy ID."),
		"address_alteration_set_id": requiredString("Address Alteration Set ID applied by this policy."),
		"policy":                    legacyPolicySchema(false),
	}}
}

func (r *addressAlterationPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *addressAlterationPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan addressAlterationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if plan.Policy == nil {
		resp.Diagnostics.AddError("Missing Address Alteration policy scope", "policy must be configured.")
		return
	}
	plan.Policy.validate(false, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateAddressAlterationPolicy(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Address Alteration policy", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetAddressAlterationPolicy(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Address Alteration policy", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *addressAlterationPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state addressAlterationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, err := r.client.GetAddressAlterationPolicy(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Address Alteration policy", err.Error())
		return
	}
	state.fromAPI(ctx, policy, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *addressAlterationPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan addressAlterationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if plan.Policy == nil {
		resp.Diagnostics.AddError("Missing Address Alteration policy scope", "policy must be configured.")
		return
	}
	plan.Policy.validate(false, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateAddressAlterationPolicy(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update Address Alteration policy", err.Error())
		return
	}
	updated, err := r.client.GetAddressAlterationPolicy(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Address Alteration policy", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *addressAlterationPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state addressAlterationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteAddressAlterationPolicy(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Address Alteration policy", err.Error())
	}
}

func (r *addressAlterationPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m addressAlterationPolicyModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.AddressAlterationPolicy {
	return client.AddressAlterationPolicy{ID: m.ID.ValueString(), AddressAlterationSetID: m.AddressAlterationSetID.ValueString(), Policy: m.Policy.toAPI(ctx, diags)}
}

func (m *addressAlterationPolicyModel) fromAPI(ctx context.Context, in client.AddressAlterationPolicy, diags *diag.Diagnostics) {
	m.ID = types.StringValue(in.ID)
	m.AddressAlterationSetID = stringValue(in.AddressAlterationSetID)
	if m.Policy == nil {
		m.Policy = &legacyPolicyModel{Comment: types.StringNull()}
	}
	m.Policy.fromAPI(ctx, in.Policy, diags)
}

type webSecurityTargetModel struct {
	ID     types.String      `tfsdk:"id"`
	Policy legacyPolicyModel `tfsdk:"policy"`
}

type webSecurityURLActionModel struct {
	ID     types.String `tfsdk:"id"`
	Action types.String `tfsdk:"action"`
	Type   types.String `tfsdk:"type"`
	Value  types.String `tfsdk:"value"`
}

type webSecurityURLPolicyModel struct {
	ID          types.String                `tfsdk:"id"`
	Description types.String                `tfsdk:"description"`
	Targets     []webSecurityTargetModel    `tfsdk:"targets"`
	URLActions  []webSecurityURLActionModel `tfsdk:"url_actions"`
}

type webSecurityURLPolicyResource struct{ client *client.Client }

func NewWebSecurityURLPolicyResource() resource.Resource { return &webSecurityURLPolicyResource{} }

func (r *webSecurityURLPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_web_security_url_policy"
}

func (r *webSecurityURLPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast Web Security URL/domain allow or block policy with its target scopes.", Attributes: map[string]schema.Attribute{
		"id":          idAttr("Mimecast Web Security policy ID."),
		"description": requiredString("Web Security policy description."),
		"targets": schema.ListNestedAttribute{Description: "Policy target scopes.", Required: true, NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"id": idAttr("Mimecast target policy ID."), "policy": legacyPolicySchema(true),
		}}},
		"url_actions": schema.ListNestedAttribute{Description: "Domains or URLs and their allow/block actions. List identity is matched by type, value, and action so returned IDs do not reorder configured items.", Required: true, NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"id":     idAttr("Mimecast URL action ID."),
			"action": schema.StringAttribute{Description: "Action taken for the URL or domain.", Required: true, Validators: []validator.String{stringvalidator.OneOf("allow", "block")}},
			"type":   schema.StringAttribute{Description: "Whether value is a URL or domain.", Required: true, Validators: []validator.String{stringvalidator.OneOf("url", "domain")}},
			"value":  requiredString("URL or domain value."),
		}}},
	}}
}

func (r *webSecurityURLPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *webSecurityURLPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan webSecurityURLPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	plan.validate(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateWebSecurityURLPolicy(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Web Security URL policy", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetWebSecurityURLPolicy(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Web Security URL policy", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *webSecurityURLPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state webSecurityURLPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, err := r.client.GetWebSecurityURLPolicy(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Web Security URL policy", err.Error())
		return
	}
	state.fromAPI(ctx, policy, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *webSecurityURLPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan webSecurityURLPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	plan.validate(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateWebSecurityURLPolicy(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update Web Security URL policy", err.Error())
		return
	}
	updated, err := r.client.GetWebSecurityURLPolicy(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Web Security URL policy", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *webSecurityURLPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state webSecurityURLPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteWebSecurityURLPolicy(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Web Security URL policy", err.Error())
	}
}

func (r *webSecurityURLPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m webSecurityURLPolicyModel) validate(diags *diag.Diagnostics) {
	if len(m.URLActions) > 5000 {
		diags.AddError("Too many Web Security URL actions", "Mimecast supports at most 5,000 URLs in one policy.")
	}
	for i := range m.Targets {
		m.Targets[i].Policy.validate(true, diags)
	}
}

func (m webSecurityURLPolicyModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.WebSecurityURLPolicy {
	out := client.WebSecurityURLPolicy{ID: m.ID.ValueString(), Description: m.Description.ValueString()}
	out.Policies = make([]client.WebSecurityTargetPolicy, 0, len(m.Targets))
	for _, target := range m.Targets {
		out.Policies = append(out.Policies, client.WebSecurityTargetPolicy{ID: target.ID.ValueString(), Policy: target.Policy.toAPI(ctx, diags)})
	}
	out.URLs = make([]client.WebSecurityURLAction, 0, len(m.URLActions))
	for _, action := range m.URLActions {
		out.URLs = append(out.URLs, client.WebSecurityURLAction{ID: action.ID.ValueString(), Action: action.Action.ValueString(), Type: action.Type.ValueString(), Value: action.Value.ValueString()})
	}
	return out
}

func (m *webSecurityURLPolicyModel) fromAPI(ctx context.Context, in client.WebSecurityURLPolicy, diags *diag.Diagnostics) {
	m.ID = types.StringValue(in.ID)
	m.Description = stringValue(in.Description)

	remainingTargets := append([]client.WebSecurityTargetPolicy(nil), in.Policies...)
	targets := make([]webSecurityTargetModel, 0, len(in.Policies))
	for _, existing := range m.Targets {
		index := findWebTarget(existing, remainingTargets)
		if index < 0 {
			continue
		}
		target := existing
		target.ID = stringValue(remainingTargets[index].ID)
		target.Policy.fromAPI(ctx, remainingTargets[index].Policy, diags)
		targets = append(targets, target)
		remainingTargets = append(remainingTargets[:index], remainingTargets[index+1:]...)
	}
	for _, item := range remainingTargets {
		target := webSecurityTargetModel{ID: stringValue(item.ID)}
		target.Policy.fromAPI(ctx, item.Policy, diags)
		targets = append(targets, target)
	}
	m.Targets = targets

	remainingActions := append([]client.WebSecurityURLAction(nil), in.URLs...)
	actions := make([]webSecurityURLActionModel, 0, len(in.URLs))
	for _, existing := range m.URLActions {
		index := findWebURLAction(existing, remainingActions)
		if index < 0 {
			continue
		}
		actions = append(actions, webSecurityURLActionModel{ID: stringValue(remainingActions[index].ID), Action: stringValue(remainingActions[index].Action), Type: stringValue(remainingActions[index].Type), Value: stringValue(remainingActions[index].Value)})
		remainingActions = append(remainingActions[:index], remainingActions[index+1:]...)
	}
	for _, item := range remainingActions {
		actions = append(actions, webSecurityURLActionModel{ID: stringValue(item.ID), Action: stringValue(item.Action), Type: stringValue(item.Type), Value: stringValue(item.Value)})
	}
	m.URLActions = actions
}

func findWebTarget(existing webSecurityTargetModel, values []client.WebSecurityTargetPolicy) int {
	if existing.ID.ValueString() != "" {
		for i := range values {
			if values[i].ID == existing.ID.ValueString() {
				return i
			}
		}
	}
	want := legacyPolicyModelIdentity(existing.Policy)
	for i := range values {
		if clientLegacyPolicyIdentity(values[i].Policy) == want {
			return i
		}
	}
	return -1
}

func findWebURLAction(existing webSecurityURLActionModel, values []client.WebSecurityURLAction) int {
	if existing.ID.ValueString() != "" {
		for i := range values {
			if values[i].ID == existing.ID.ValueString() {
				return i
			}
		}
	}
	want := strings.Join([]string{existing.Type.ValueString(), existing.Value.ValueString(), existing.Action.ValueString()}, "\x00")
	for i := range values {
		if strings.Join([]string{values[i].Type, values[i].Value, values[i].Action}, "\x00") == want {
			return i
		}
	}
	return -1
}

func legacyPolicyModelIdentity(policy legacyPolicyModel) string {
	return strings.Join([]string{policy.Description.ValueString(), policy.From.Type.ValueString(), legacyTargetValue(policy.From), policy.To.Type.ValueString(), legacyTargetValue(policy.To)}, "\x00")
}

func clientLegacyPolicyIdentity(policy client.LegacyPolicyScope) string {
	return strings.Join([]string{policy.Description, policy.From.Type, clientLegacyTargetValue(policy.From), policy.To.Type, clientLegacyTargetValue(policy.To)}, "\x00")
}

func legacyTargetValue(target legacyPolicyTargetModel) string {
	return strings.Join([]string{target.GroupID.ValueString(), target.EmailDomain.ValueString(), target.EmailAddress.ValueString(), target.AttributeID.ValueString(), target.AttributeValue.ValueString()}, "\x00")
}

func clientLegacyTargetValue(target client.LegacyPolicyTarget) string {
	attributeID, attributeValue := "", ""
	if target.Attribute != nil {
		attributeID, attributeValue = target.Attribute.ID, target.Attribute.Value
	}
	return strings.Join([]string{target.ResolvedGroupID(), target.EmailDomain, target.EmailAddress, attributeID, attributeValue}, "\x00")
}

type threatReportingSubscriptionModel struct {
	ID                   types.String `tfsdk:"id"`
	NotificationURL      types.String `tfsdk:"notification_url"`
	ResourceType         types.String `tfsdk:"resource_type"`
	ClientStateWO        types.String `tfsdk:"client_state_wo"`
	OldClientStateWO     types.String `tfsdk:"old_client_state_wo"`
	ClientStateWOVersion types.Int64  `tfsdk:"client_state_wo_version"`
	CreationDateTime     types.String `tfsdk:"creation_date_time"`
	ExpirationDateTime   types.String `tfsdk:"expiration_date_time"`
}

type threatReportingSubscriptionResource struct{ client *client.Client }

func NewThreatReportingSubscriptionResource() resource.Resource {
	return &threatReportingSubscriptionResource{}
}

func (r *threatReportingSubscriptionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threat_reporting_subscription"
}

func (r *threatReportingSubscriptionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast threat-reporting webhook subscription. Client state values are write-only and never stored.", Attributes: map[string]schema.Attribute{
		"id":                      idAttr("Mimecast subscription ID."),
		"notification_url":        schema.StringAttribute{Description: "Public HTTPS callback URL. The subscription API cannot update this value, so changes replace the resource.", Optional: true, Validators: []validator.String{httpsURLValidator{}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"resource_type":           schema.StringAttribute{Description: "Subscribed resource type. Mimecast currently supports only threat-analysis.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("threat-analysis")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
		"client_state_wo":         schema.StringAttribute{Description: "Client state used to verify webhook notifications. Write-only and required when creating or renewing.", Optional: true, WriteOnly: true, Sensitive: true},
		"old_client_state_wo":     schema.StringAttribute{Description: "Previous client state required when rotating client_state_wo. If omitted during renewal, client_state_wo is reused as the old value.", Optional: true, WriteOnly: true, Sensitive: true},
		"client_state_wo_version": schema.Int64Attribute{Description: "Version trigger for client_state_wo. Increment to renew or rotate the subscription.", Optional: true, Validators: []validator.Int64{nonNegativeInt64Validator{}}},
		"creation_date_time":      computedString("Subscription creation time returned by Mimecast."),
		"expiration_date_time":    computedString("Subscription expiration time returned by Mimecast."),
	}}
}

func (r *threatReportingSubscriptionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *threatReportingSubscriptionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan threatReportingSubscriptionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("client_state_wo"), &plan.ClientStateWO)...)
	if plan.NotificationURL.ValueString() == "" || plan.ResourceType.ValueString() == "" || plan.ClientStateWO.ValueString() == "" {
		resp.Diagnostics.AddError("Incomplete threat-reporting subscription", "notification_url, resource_type, and client_state_wo are required when creating a subscription.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateThreatReportingSubscription(ctx, plan.NotificationURL.ValueString(), plan.ResourceType.ValueString(), plan.ClientStateWO.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create threat-reporting subscription", err.Error())
		return
	}
	plan.ID = types.StringValue(created.SubscriptionID)
	read, err := r.client.GetThreatReportingSubscription(ctx, created.SubscriptionID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created threat-reporting subscription", err.Error())
		return
	}
	plan.fromAPI(read)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *threatReportingSubscriptionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state threatReportingSubscriptionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	subscription, err := r.client.GetThreatReportingSubscription(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read threat-reporting subscription", err.Error())
		return
	}
	state.fromAPI(subscription)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *threatReportingSubscriptionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan threatReportingSubscriptionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("client_state_wo"), &plan.ClientStateWO)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("old_client_state_wo"), &plan.OldClientStateWO)...)
	if plan.ClientStateWO.ValueString() == "" {
		resp.Diagnostics.AddError("Missing client state", "client_state_wo is required when renewing a threat-reporting subscription.")
		return
	}
	oldClientState := plan.OldClientStateWO.ValueString()
	if oldClientState == "" {
		oldClientState = plan.ClientStateWO.ValueString()
	}
	if _, err := r.client.UpdateThreatReportingSubscription(ctx, plan.ID.ValueString(), oldClientState, plan.ClientStateWO.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to renew threat-reporting subscription", err.Error())
		return
	}
	updated, err := r.client.GetThreatReportingSubscription(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read renewed threat-reporting subscription", err.Error())
		return
	}
	plan.fromAPI(updated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *threatReportingSubscriptionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state threatReportingSubscriptionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteThreatReportingSubscription(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete threat-reporting subscription", err.Error())
	}
}

func (r *threatReportingSubscriptionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m *threatReportingSubscriptionModel) fromAPI(in client.ThreatReportingSubscription) {
	if in.SubscriptionID != "" {
		m.ID = types.StringValue(in.SubscriptionID)
	}
	// List responses do not include notificationURL. Preserve config/state.
	if in.NotificationURL != "" {
		m.NotificationURL = stringValue(in.NotificationURL)
	}
	if in.ResourceType != "" {
		m.ResourceType = stringValue(in.ResourceType)
	}
	m.CreationDateTime = stringValue(in.CreationDateTime)
	m.ExpirationDateTime = stringValue(in.ExpirationDateTime)
	// Write-only client state is accepted only from configuration for create or
	// renewal and must never be persisted in Terraform state.
	m.ClientStateWO = types.StringNull()
	m.OldClientStateWO = types.StringNull()
}

type threatReportingSubscriptionInventoryItemModel struct {
	ID                 types.String `tfsdk:"id"`
	NotificationURL    types.String `tfsdk:"notification_url"`
	ResourceType       types.String `tfsdk:"resource_type"`
	CreationDateTime   types.String `tfsdk:"creation_date_time"`
	ExpirationDateTime types.String `tfsdk:"expiration_date_time"`
}

type threatReportingSubscriptionsModel struct {
	ID    types.String                                    `tfsdk:"id"`
	Items []threatReportingSubscriptionInventoryItemModel `tfsdk:"items"`
}

func NewThreatReportingSubscriptionsDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable threat-reporting subscription inventory ID."),
		"items": dsItems(map[string]dsschema.Attribute{
			"id": dsID("Threat-reporting subscription ID."), "notification_url": dsSensitiveString("Webhook notification URL when returned by Mimecast."),
			"resource_type": dsString("Subscribed resource type."), "creation_date_time": dsString("Subscription creation time."), "expiration_date_time": dsString("Subscription expiration time."),
		}),
	}
	return newTypedDataSource("threat_reporting_subscriptions", "Read every threat-reporting subscription without exposing client-state secrets.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListThreatReportingSubscriptions(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read threat-reporting subscriptions", err.Error())
			return
		}
		items := make([]threatReportingSubscriptionInventoryItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, threatReportingSubscriptionInventoryItemModel{
				ID: stringValue(item.SubscriptionID), NotificationURL: stringValue(item.NotificationURL), ResourceType: stringValue(item.ResourceType),
				CreationDateTime: stringValue(item.CreationDateTime), ExpirationDateTime: stringValue(item.ExpirationDateTime),
			})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &threatReportingSubscriptionsModel{ID: types.StringValue("threat_reporting_subscriptions"), Items: items})...)
	})
}

type httpsURLValidator struct{}

func (httpsURLValidator) Description(context.Context) string { return "must be an absolute HTTPS URL" }
func (httpsURLValidator) MarkdownDescription(context.Context) string {
	return "must be an absolute HTTPS URL"
}
func (httpsURLValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return
	}
	parsed, err := url.Parse(req.ConfigValue.ValueString())
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid notification URL", "notification_url must be an absolute HTTPS URL.")
	}
}
