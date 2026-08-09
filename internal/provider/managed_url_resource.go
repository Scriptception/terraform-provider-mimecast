package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type managedURLModel struct {
	ID                   types.String `tfsdk:"id"`
	URL                  types.String `tfsdk:"url"`
	Action               types.String `tfsdk:"action"`
	MatchType            types.String `tfsdk:"match_type"`
	Comment              types.String `tfsdk:"comment"`
	DisableLogClick      types.Bool   `tfsdk:"disable_log_click"`
	DisableRewrite       types.Bool   `tfsdk:"disable_rewrite"`
	DisableUserAwareness types.Bool   `tfsdk:"disable_user_awareness"`
}

type managedURLResource struct{ client *client.Client }

const (
	managedURLAccessTokenSummary      = "Unsupported managed URL"
	managedURLAccessTokenDetail       = "Managed URLs whose decoded query parameter name is access_token are intentionally unsupported because credential values must not enter Terraform configuration or state."
	managedURLUnreconstructibleDetail = "Mimecast did not return enough URL components to reconstruct the managed URL."
	managedURLInventoryNotFoundDetail = "Mimecast did not return a managed URL matching the requested ID."
	managedURLCreatedNotFoundDetail   = "Mimecast did not return the created ID from the managed URL inventory."
)

func NewManagedURLResource() resource.Resource { return &managedURLResource{} }
func (r *managedURLResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_managed_url"
}
func (r *managedURLResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	urlAttribute := requiredReplaceString("URL or domain to manage. Do not include URL fragments or an access_token query parameter.")
	urlAttribute.Validators = []validator.String{managedURLAccessTokenValidator{}}
	resp.Schema = schema.Schema{Description: "Manage a Mimecast Targeted Threat Protection managed URL. Mimecast filtered reads can omit an existing record or return a different opaque ID, so the provider preserves the create/import ID and confirms absence against the unfiltered inventory.", Attributes: map[string]schema.Attribute{
		"id":                     idAttr("Mimecast managed URL ID."),
		"url":                    urlAttribute,
		"action":                 requiredReplaceString("Managed URL action: `block` or `permit`."),
		"match_type":             optionalComputedReplaceString("Match type: `explicit` or `domain`."),
		"comment":                optionalComputedReplaceString("Tracking comment."),
		"disable_log_click":      optionalComputedReplaceBool("Disable user click logging. Applies to permitted URLs."),
		"disable_rewrite":        optionalComputedReplaceBool("Disable URL rewriting. Applies to permitted URLs."),
		"disable_user_awareness": optionalComputedReplaceBool("Disable user awareness challenges. Applies to permitted URLs."),
	}}
}
func (r *managedURLResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}
func (r *managedURLResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan managedURLModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if rejectManagedURLValue(plan.URL.ValueString(), &resp.Diagnostics) {
		return
	}
	id, err := r.client.CreateManagedURL(ctx, plan.toAPI())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create managed URL", err.Error())
		return
	}
	if id == "" {
		resp.Diagnostics.AddError("Unable to create managed URL", "Mimecast did not return an ID for the managed URL.")
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.ListManagedURLs(ctx, "", false)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created managed URL", err.Error())
		return
	}
	item, found := managedURLByID(created, id)
	if !found {
		resp.Diagnostics.AddError("Unable to read created managed URL", managedURLCreatedNotFoundDetail)
		return
	}
	if !hydrateManagedURLModel(&plan, item, "Unable to read created managed URL", &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *managedURLResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state managedURLModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if rejectManagedURLValue(state.URL.ValueString(), &resp.Diagnostics) {
		return
	}
	storedID := state.ID.ValueString()
	if !state.URL.IsNull() && !state.URL.IsUnknown() && state.URL.ValueString() != "" {
		items, err := r.client.ListManagedURLs(ctx, state.URL.ValueString(), true)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read managed URL", err.Error())
			return
		}
		if item, found := managedURLByID(items, storedID); found {
			if hydrateManagedURLModel(&state, item, "Unable to read managed URL", &resp.Diagnostics) {
				resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			}
			return
		}
		if item, found := managedURLSemanticMatch(items, state); found {
			if hydrateManagedURLModel(&state, item, "Unable to read managed URL", &resp.Diagnostics) {
				resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			}
			return
		}
	}

	inventory, err := r.client.ListManagedURLs(ctx, "", false)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read managed URL", err.Error())
		return
	}
	if item, found := managedURLByID(inventory, storedID); found {
		if hydrateManagedURLModel(&state, item, "Unable to read managed URL", &resp.Diagnostics) {
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		}
		return
	}
	resp.State.RemoveResource(ctx)
}
func (r *managedURLResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan managedURLModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if rejectManagedURLValue(plan.URL.ValueString(), &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.AddError("Update not supported", "Mimecast API 2.0 does not expose a documented update endpoint for managed URLs. Delete and recreate the resource.")
}
func (r *managedURLResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state managedURLModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedURL(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete managed URL", err.Error())
	}
}
func (r *managedURLResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	items, err := r.client.ListManagedURLs(ctx, "", false)
	if err != nil {
		resp.Diagnostics.AddError("Unable to import managed URL", "Mimecast could not read the managed URL inventory.")
		return
	}
	item, found := managedURLByID(items, req.ID)
	if !found {
		resp.Diagnostics.AddError("Unable to import managed URL", managedURLInventoryNotFoundDetail)
		return
	}
	state := managedURLModel{ID: types.StringValue(req.ID)}
	if !hydrateManagedURLModel(&state, item, "Unable to import managed URL", &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func managedURLByID(items []client.ManagedURL, id string) (client.ManagedURL, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return client.ManagedURL{}, false
}

func managedURLSemanticMatch(items []client.ManagedURL, state managedURLModel) (client.ManagedURL, bool) {
	for _, item := range items {
		if state.semanticallyMatches(item) {
			return item, true
		}
	}
	return client.ManagedURL{}, false
}

func hydrateManagedURLModel(model *managedURLModel, item client.ManagedURL, summary string, diagnostics *diag.Diagnostics) bool {
	if client.ManagedURLHasAccessTokenQuery(item) {
		diagnostics.AddError(managedURLAccessTokenSummary, managedURLAccessTokenDetail)
		return false
	}
	if item.URL == "" {
		diagnostics.AddError(summary, managedURLUnreconstructibleDetail)
		return false
	}
	if !model.fromAPI(item) {
		diagnostics.AddError(managedURLAccessTokenSummary, managedURLAccessTokenDetail)
		return false
	}
	return true
}

func rejectManagedURLValue(value string, diagnostics *diag.Diagnostics) bool {
	if !client.ManagedURLValueHasAccessTokenQuery(value) {
		return false
	}
	diagnostics.AddError(managedURLAccessTokenSummary, managedURLAccessTokenDetail)
	return true
}

func (m managedURLModel) toAPI() client.ManagedURL {
	return client.ManagedURL{ID: m.ID.ValueString(), URL: m.URL.ValueString(), Action: m.Action.ValueString(), MatchType: m.MatchType.ValueString(), Comment: m.Comment.ValueString(), DisableLogClick: boolPtr(m.DisableLogClick), DisableRewrite: boolPtr(m.DisableRewrite), DisableUserAwareness: boolPtr(m.DisableUserAwareness)}
}
func (m *managedURLModel) fromAPI(in client.ManagedURL) bool {
	if client.ManagedURLHasAccessTokenQuery(in) {
		return false
	}
	if m.ID.IsNull() || m.ID.IsUnknown() || m.ID.ValueString() == "" {
		m.ID = stringValue(in.ID)
	}
	m.URL = stringValue(in.URL)
	m.Action = stringValue(in.Action)
	m.MatchType = stringValue(in.MatchType)
	m.Comment = stringValue(in.Comment)
	m.DisableLogClick = boolValue(in.DisableLogClick)
	m.DisableRewrite = boolValue(in.DisableRewrite)
	m.DisableUserAwareness = boolValue(in.DisableUserAwareness)
	return true
}

func (m managedURLModel) semanticallyMatches(in client.ManagedURL) bool {
	if in.URL == "" || client.ManagedURLHasAccessTokenQuery(in) {
		return false
	}
	var candidate managedURLModel
	if !candidate.fromAPI(in) {
		return false
	}
	return m.URL.Equal(candidate.URL) &&
		m.Action.Equal(candidate.Action) &&
		m.MatchType.Equal(candidate.MatchType) &&
		m.Comment.Equal(candidate.Comment) &&
		m.DisableLogClick.Equal(candidate.DisableLogClick) &&
		m.DisableRewrite.Equal(candidate.DisableRewrite) &&
		m.DisableUserAwareness.Equal(candidate.DisableUserAwareness)
}
