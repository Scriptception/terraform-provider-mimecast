package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type profileGroupModel struct {
	ID          types.String `tfsdk:"id"`
	Description types.String `tfsdk:"description"`
	ParentID    types.String `tfsdk:"parent_id"`
	Source      types.String `tfsdk:"source"`
	UserCount   types.Int64  `tfsdk:"user_count"`
	GroupCount  types.Int64  `tfsdk:"group_count"`
}

type profileGroupResource struct{ client *client.Client }

func NewProfileGroupResource() resource.Resource { return &profileGroupResource{} }
func (r *profileGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_profile_group"
}
func (r *profileGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast Cloud Gateway profile group.", Attributes: map[string]schema.Attribute{
		"id":          idAttr("Profile group ID."),
		"description": requiredString("Profile group description."),
		"parent_id":   optionalString("Parent group ID. Mimecast uses root when omitted."),
		"source":      computedString("Group source, such as `cloud` or `ldap`."),
		"user_count":  schema.Int64Attribute{Description: "Number of users in the group.", Computed: true},
		"group_count": schema.Int64Attribute{Description: "Number of child groups.", Computed: true},
	}}
}
func (r *profileGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}
func (r *profileGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan profileGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateProfileGroup(ctx, client.ProfileGroup{Description: plan.Description.ValueString(), ParentID: plan.ParentID.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create profile group", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetProfileGroup(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created profile group", err.Error())
		return
	}
	plan.fromAPI(created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *profileGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state profileGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetProfileGroup(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read profile group", err.Error())
		return
	}
	state.fromAPI(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *profileGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan profileGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateProfileGroup(ctx, client.ProfileGroup{ID: plan.ID.ValueString(), Description: plan.Description.ValueString(), ParentID: plan.ParentID.ValueString()}); err != nil {
		resp.Diagnostics.AddError("Unable to update profile group", err.Error())
		return
	}
	updated, err := r.client.GetProfileGroup(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated profile group", err.Error())
		return
	}
	plan.fromAPI(updated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (m *profileGroupModel) fromAPI(in client.ProfileGroup) {
	m.Description = stringValue(in.Description)
	m.ParentID = stringValue(in.ParentID)
	m.Source = stringValue(in.Source)
	m.UserCount = types.Int64Value(in.UserCount)
	m.GroupCount = types.Int64Value(in.GroupCount)
}
func (r *profileGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state profileGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteProfileGroup(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete profile group", err.Error())
	}
}
func (r *profileGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

type profileGroupMemberModel struct {
	ID           types.String `tfsdk:"id"`
	GroupID      types.String `tfsdk:"group_id"`
	EmailAddress types.String `tfsdk:"email_address"`
	Domain       types.String `tfsdk:"domain"`
	Note         types.String `tfsdk:"note"`
	Name         types.String `tfsdk:"name"`
	Internal     types.Bool   `tfsdk:"internal"`
	Type         types.String `tfsdk:"type"`
}

type profileGroupMemberResource struct{ client *client.Client }

func NewProfileGroupMemberResource() resource.Resource { return &profileGroupMemberResource{} }
func (r *profileGroupMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_profile_group_member"
}
func (r *profileGroupMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage membership of a user email address or domain in a Mimecast profile group.", Attributes: map[string]schema.Attribute{
		"id":            idAttr("Composite ID in the form `group_id/member`."),
		"group_id":      requiredReplaceString("Profile group ID."),
		"email_address": optionalReplaceStringWithValidators("Member email address. Use either email_address or domain.", stringvalidator.ExactlyOneOf(path.MatchRoot("domain"))),
		"domain":        optionalReplaceString("Member domain. Use either domain or email_address."),
		"note":          optionalReplaceString("Optional note when adding the member."),
		"name":          computedString("Member display name returned by Mimecast."),
		"internal":      schema.BoolAttribute{Description: "Whether the member is internal.", Computed: true},
		"type":          computedString("Address type returned by Mimecast."),
	}}
}
func (r *profileGroupMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}
func (r *profileGroupMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan profileGroupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validateMemberIdentity(plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.AddProfileGroupMembers(ctx, plan.GroupID.ValueString(), []client.GroupMember{plan.member()}); err != nil {
		resp.Diagnostics.AddError("Unable to add profile group member", err.Error())
		return
	}
	plan.ID = types.StringValue(normalizeCompositeID(plan.GroupID.ValueString(), plan.memberKey()))
	if !r.readMember(ctx, &plan, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *profileGroupMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state profileGroupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.readMember(ctx, &state, &resp.Diagnostics) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	if !resp.Diagnostics.HasError() {
		resp.State.RemoveResource(ctx)
	}
}
func (r *profileGroupMemberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}
func (r *profileGroupMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state profileGroupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RemoveProfileGroupMembers(ctx, state.GroupID.ValueString(), []client.GroupMember{state.member()}); err != nil {
		resp.Diagnostics.AddError("Unable to remove profile group member", err.Error())
	}
}
func (r *profileGroupMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid import ID", "Use `group_id/member`, where member is an email address or domain.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("group_id"), parts[0])...)
	if strings.Contains(parts[1], "@") {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("email_address"), parts[1])...)
	} else {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("domain"), parts[1])...)
	}
}
func (m profileGroupMemberModel) member() client.GroupMember {
	return client.GroupMember{EmailAddress: m.EmailAddress.ValueString(), Domain: m.Domain.ValueString(), Note: m.Note.ValueString()}
}
func (m profileGroupMemberModel) memberKey() string {
	if m.EmailAddress.ValueString() != "" {
		return strings.ToLower(m.EmailAddress.ValueString())
	}
	return strings.ToLower(m.Domain.ValueString())
}

func (r *profileGroupMemberResource) readMember(ctx context.Context, state *profileGroupMemberModel, diags *diag.Diagnostics) bool {
	emailIdentity := state.EmailAddress.ValueString()
	domainIdentity := state.Domain.ValueString()
	if (emailIdentity != "") == (domainIdentity != "") {
		diags.AddError("Invalid profile group member", "State must contain exactly one of email_address or domain.")
		return false
	}

	items, err := r.client.ListProfileGroupMembers(ctx, state.GroupID.ValueString())
	if err != nil {
		diags.AddError("Unable to read profile group members", err.Error())
		return false
	}
	for _, item := range items {
		if emailIdentity != "" && strings.EqualFold(item.EmailAddress, emailIdentity) {
			state.Domain = types.StringNull()
			state.Name = stringValue(item.Name)
			state.Type = stringValue(item.Type)
			state.Internal = boolValue(item.Internal)
			return true
		}
		if domainIdentity != "" && strings.EqualFold(item.Domain, domainIdentity) {
			state.EmailAddress = types.StringNull()
			state.Name = stringValue(item.Name)
			state.Type = stringValue(item.Type)
			state.Internal = boolValue(item.Internal)
			return true
		}
	}
	return false
}
func validateMemberIdentity(m profileGroupMemberModel, diags *diag.Diagnostics) {
	hasEmail := m.EmailAddress.ValueString() != ""
	hasDomain := m.Domain.ValueString() != ""
	if hasEmail == hasDomain {
		diags.AddError("Invalid profile group member", "Set exactly one of email_address or domain.")
	}
}

type outboundIPAddressesModel struct {
	ID                  types.String `tfsdk:"id"`
	OutboundIPAddresses types.Set    `tfsdk:"outbound_ip_addresses"`
}

type outboundIPAddressesResource struct{ client *client.Client }

func NewOutboundIPAddressesResource() resource.Resource { return &outboundIPAddressesResource{} }
func (r *outboundIPAddressesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_outbound_ip_addresses"
}
func (r *outboundIPAddressesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage the account-level Mimecast Cloud Gateway outbound IP address list.", Attributes: map[string]schema.Attribute{
		"id":                    idAttr("Singleton ID, always `outbound_ip_addresses`."),
		"outbound_ip_addresses": schema.SetAttribute{Description: "Canonical set of outbound IP addresses to assign for the account.", Required: true, ElementType: types.StringType},
	}}
}
func (r *outboundIPAddressesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}
func (r *outboundIPAddressesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.upsert(ctx, req.Plan, &resp.Diagnostics, resp.State.Set)
}
func (r *outboundIPAddressesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state outboundIPAddressesModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ips, err := r.client.GetOutboundIPAddresses(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read outbound IP addresses", err.Error())
		return
	}
	var d diag.Diagnostics
	state.ID = types.StringValue("outbound_ip_addresses")
	state.OutboundIPAddresses, d = setFromStrings(ctx, ips)
	resp.Diagnostics.Append(d...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *outboundIPAddressesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.upsert(ctx, req.Plan, &resp.Diagnostics, resp.State.Set)
}
func (r *outboundIPAddressesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.DeleteOutboundIPAddresses(ctx); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete outbound IP addresses", err.Error())
	}
}
func (r *outboundIPAddressesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), "outbound_ip_addresses")...)
}

type planReader interface {
	Get(context.Context, any) diag.Diagnostics
}
type stateSetter func(context.Context, any) diag.Diagnostics

func (r *outboundIPAddressesResource) upsert(ctx context.Context, plan planReader, diags *diag.Diagnostics, set stateSetter) {
	var model outboundIPAddressesModel
	diags.Append(plan.Get(ctx, &model)...)
	if diags.HasError() {
		return
	}
	ips, d := stringsFromSet(ctx, model.OutboundIPAddresses)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if err := r.client.PutOutboundIPAddresses(ctx, ips); err != nil {
		diags.AddError("Unable to update outbound IP addresses", err.Error())
		return
	}
	ips, err := r.client.GetOutboundIPAddresses(ctx)
	if err != nil {
		diags.AddError("Unable to read updated outbound IP addresses", err.Error())
		return
	}
	model.ID = types.StringValue("outbound_ip_addresses")
	model.OutboundIPAddresses, d = setFromStrings(ctx, ips)
	diags.Append(d...)
	diags.Append(set(ctx, &model)...)
}
