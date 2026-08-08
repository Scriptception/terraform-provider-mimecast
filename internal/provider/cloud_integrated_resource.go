package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type cloudIntegratedPolicyModel struct {
	ID                    types.String                         `tfsdk:"id"`
	PolicyID              types.String                         `tfsdk:"policy_id"`
	AccountID             types.String                         `tfsdk:"account_id"`
	Name                  types.String                         `tfsdk:"name"`
	Description           types.String                         `tfsdk:"description"`
	ProtectionMode        types.String                         `tfsdk:"protection_mode"`
	Targets               *cloudIntegratedTargetsModel         `tfsdk:"targets"`
	Actions               *cloudIntegratedActionsModel         `tfsdk:"actions"`
	Alerts                *cloudIntegratedAlertsModel          `tfsdk:"alerts"`
	SecurityEngines       *cloudIntegratedSecurityEnginesModel `tfsdk:"security_engines"`
	TargetsSHA256         types.String                         `tfsdk:"targets_sha256"`
	ActionsSHA256         types.String                         `tfsdk:"actions_sha256"`
	AlertsSHA256          types.String                         `tfsdk:"alerts_sha256"`
	SecurityEnginesSHA256 types.String                         `tfsdk:"security_engines_sha256"`
}

type cloudIntegratedTargetsModel struct {
	Senders      *cloudIntegratedRouteTargetModel `tfsdk:"senders"`
	Recipients   *cloudIntegratedRouteTargetModel `tfsdk:"recipients"`
	Exceptions   *cloudIntegratedExceptionModel   `tfsdk:"exceptions"`
	AddressMatch types.String                     `tfsdk:"address_match"`
}

type cloudIntegratedRouteTargetModel struct {
	Route    types.String `tfsdk:"route"`
	Emails   types.Set    `tfsdk:"emails"`
	GroupIDs types.Set    `tfsdk:"group_ids"`
	Domains  types.Set    `tfsdk:"domains"`
}

type cloudIntegratedExceptionModel struct {
	Emails   types.Set `tfsdk:"emails"`
	GroupIDs types.Set `tfsdk:"group_ids"`
	Domains  types.Set `tfsdk:"domains"`
}

type cloudIntegratedActionsModel struct {
	Malware       types.String `tfsdk:"malware"`
	Phishing      types.String `tfsdk:"phishing"`
	Untrustworthy types.String `tfsdk:"untrustworthy"`
	Spam          types.String `tfsdk:"spam"`
}

type cloudIntegratedAlertsModel struct {
	Malware       types.Bool `tfsdk:"malware"`
	Phishing      types.Bool `tfsdk:"phishing"`
	Untrustworthy types.Bool `tfsdk:"untrustworthy"`
	Spam          types.Bool `tfsdk:"spam"`
}

type cloudIntegratedSecurityEnginesModel struct {
	URLClick      *cloudIntegratedURLClickEngineModel      `tfsdk:"url_click"`
	Phishing      *cloudIntegratedPhishingEngineModel      `tfsdk:"phishing"`
	Impersonation *cloudIntegratedImpersonationEngineModel `tfsdk:"impersonation"`
	Attachments   *cloudIntegratedAttachmentsEngineModel   `tfsdk:"attachments"`
}

type cloudIntegratedURLClickEngineModel struct {
	Sensitivity              types.String `tfsdk:"sensitivity"`
	ScanURLsInAttachment     types.Bool   `tfsdk:"scan_urls_in_attachment"`
	RewriteEnabled           types.Bool   `tfsdk:"rewrite_enabled"`
	RewriteMode              types.String `tfsdk:"rewrite_mode"`
	ForceSecureConnection    types.Bool   `tfsdk:"force_secure_connection"`
	BlockDangerousExtensions types.Bool   `tfsdk:"block_dangerous_extensions"`
	UserIdentification       types.String `tfsdk:"user_identification"`
	BIUnclassifiedURLs       types.Bool   `tfsdk:"bi_unclassified_urls"`
	BIAdminViewing           types.Bool   `tfsdk:"bi_admin_viewing"`
	BIEnterText              types.Bool   `tfsdk:"bi_enter_text"`
	BIPasteText              types.Bool   `tfsdk:"bi_paste_text"`
	BICopyText               types.Bool   `tfsdk:"bi_copy_text"`
	ScanOutboundEmails       types.Bool   `tfsdk:"scan_outbound_emails"`
}

type cloudIntegratedPhishingEngineModel struct {
	SensitivityPhishingHigh      types.Int64 `tfsdk:"sensitivity_phishing_high"`
	SensitivityUntrustworthyHigh types.Int64 `tfsdk:"sensitivity_untrustworthy_high"`
	ScanOutboundEmails           types.Bool  `tfsdk:"scan_outbound_emails"`
}

type cloudIntegratedImpersonationEngineModel struct {
	CodeBreakerStatus types.String `tfsdk:"code_breaker_status"`
	ReportingStatus   types.String `tfsdk:"reporting_status"`
	SilencerStatus    types.String `tfsdk:"silencer_status"`
}

type cloudIntegratedAttachmentsEngineModel struct {
	SandboxEnabled     types.Bool   `tfsdk:"sandbox_enabled"`
	UnreadableArchives types.String `tfsdk:"unreadable_archives"`
}

type cloudIntegratedPolicyResource struct{ client *client.Client }

func NewCloudIntegratedPolicyResource() resource.Resource { return &cloudIntegratedPolicyResource{} }

func (r *cloudIntegratedPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_integrated_policy"
}

func (r *cloudIntegratedPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a fully typed Mimecast Email Security Cloud Integrated policy.", Attributes: cloudIntegratedResourceAttributes()}
}

func cloudIntegratedResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":                      idAttr("Cloud Integrated policy ID."),
		"policy_id":               computedString("Policy ID returned by Mimecast."),
		"account_id":              schema.StringAttribute{Description: "Mimecast account ID returned by the API.", Computed: true, Sensitive: true},
		"name":                    requiredString("Policy name."),
		"description":             optionalComputedString("Policy description."),
		"protection_mode":         schema.StringAttribute{Description: "Protection mode.", Required: true, Validators: []validator.String{stringvalidator.OneOf("ACTIVE", "MONITOR_ONLY")}},
		"targets":                 cloudIntegratedTargetsResourceAttribute(true),
		"actions":                 cloudIntegratedActionsResourceAttribute(),
		"alerts":                  cloudIntegratedAlertsResourceAttribute(),
		"security_engines":        cloudIntegratedSecurityEnginesResourceAttribute(),
		"targets_sha256":          computedString("Canonical SHA-256 of the typed targets object."),
		"actions_sha256":          computedString("Canonical SHA-256 of the typed actions object."),
		"alerts_sha256":           computedString("Canonical SHA-256 of the typed alerts object."),
		"security_engines_sha256": computedString("Canonical SHA-256 of the typed security-engines object."),
	}
}

func cloudIntegratedTargetsResourceAttribute(required bool) schema.SingleNestedAttribute {
	attribute := schema.SingleNestedAttribute{Description: "Policy target selectors.", Attributes: map[string]schema.Attribute{
		"senders":       cloudIntegratedRouteTargetResourceAttribute("Sender selectors."),
		"recipients":    cloudIntegratedRouteTargetResourceAttribute("Recipient selectors."),
		"exceptions":    cloudIntegratedExceptionResourceAttribute(),
		"address_match": schema.StringAttribute{Description: "Address component used for matching.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("HEADER", "ENVELOPE", "BOTH")}},
	}}
	if required {
		attribute.Required = true
	} else {
		attribute.Optional = true
		attribute.Computed = true
	}
	return attribute
}

func cloudIntegratedRouteTargetResourceAttribute(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{Description: description, Optional: true, Computed: true, Attributes: map[string]schema.Attribute{
		"route":     schema.StringAttribute{Description: "Address route selector.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("ALL", "INTERNAL", "EXTERNAL")}},
		"emails":    cloudIntegratedStringSetResource("Email selectors.", true),
		"group_ids": cloudIntegratedStringSetResource("Directory group IDs.", false),
		"domains":   cloudIntegratedStringSetResource("Domain selectors.", false),
	}}
}

func cloudIntegratedExceptionResourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{Description: "Target exceptions.", Optional: true, Computed: true, Attributes: map[string]schema.Attribute{
		"emails":    cloudIntegratedStringSetResource("Exception email addresses.", true),
		"group_ids": cloudIntegratedStringSetResource("Exception directory group IDs.", false),
		"domains":   cloudIntegratedStringSetResource("Exception domains.", false),
	}}
}

func cloudIntegratedStringSetResource(description string, sensitive bool) schema.SetAttribute {
	return schema.SetAttribute{Description: description, Optional: true, Computed: true, Sensitive: sensitive, ElementType: types.StringType}
}

func cloudIntegratedActionsResourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{Description: "Disposition actions by threat class.", Optional: true, Computed: true, Attributes: map[string]schema.Attribute{
		"malware":       cloudIntegratedActionResource("Malware action.", false),
		"phishing":      cloudIntegratedActionResource("Phishing action.", false),
		"untrustworthy": cloudIntegratedActionResource("Untrustworthy-message action.", true),
		"spam":          cloudIntegratedActionResource("Spam action.", true),
	}}
}

func cloudIntegratedActionResource(description string, allowJunk bool) schema.StringAttribute {
	values := []string{"BLOCK", "QUARANTINE", "DO_NOTHING"}
	if allowJunk {
		values = append(values, "MOVE_TO_JUNK")
	}
	return schema.StringAttribute{Description: description, Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf(values...)}}
}

func cloudIntegratedAlertsResourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{Description: "Alert toggles by threat class.", Optional: true, Computed: true, Attributes: map[string]schema.Attribute{
		"malware":       optionalComputedBool("Alert on malware."),
		"phishing":      optionalComputedBool("Alert on phishing."),
		"untrustworthy": optionalComputedBool("Alert on untrustworthy messages."),
		"spam":          optionalComputedBool("Alert on spam."),
	}}
}

func cloudIntegratedSecurityEnginesResourceAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{Description: "Security-engine configuration.", Optional: true, Computed: true, Attributes: map[string]schema.Attribute{
		"url_click":     schema.SingleNestedAttribute{Optional: true, Computed: true, Attributes: cloudIntegratedURLClickResourceAttributes()},
		"phishing":      schema.SingleNestedAttribute{Optional: true, Computed: true, Attributes: cloudIntegratedPhishingResourceAttributes()},
		"impersonation": schema.SingleNestedAttribute{Optional: true, Computed: true, Attributes: cloudIntegratedImpersonationResourceAttributes()},
		"attachments":   schema.SingleNestedAttribute{Optional: true, Computed: true, Attributes: cloudIntegratedAttachmentsResourceAttributes()},
	}}
}

func cloudIntegratedURLClickResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"sensitivity":                schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("LOW", "MEDIUM", "HIGH")}},
		"scan_urls_in_attachment":    optionalComputedBool("Scan URLs in attachments."),
		"rewrite_enabled":            optionalComputedBool("Enable URL rewriting."),
		"rewrite_mode":               schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("MODERATE", "AGGRESSIVE", "RELAXED")}},
		"force_secure_connection":    optionalComputedBool("Require a secure connection."),
		"block_dangerous_extensions": optionalComputedBool("Block dangerous extensions."),
		"user_identification":        schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("BASIC", "ADV_DEVICE_ENROLLMENT", "ADV_SSO")}},
		"bi_unclassified_urls":       optionalComputedBool("Browser Isolation for unclassified URLs."),
		"bi_admin_viewing":           optionalComputedBool("Allow Browser Isolation administrator viewing."),
		"bi_enter_text":              optionalComputedBool("Allow entering text in Browser Isolation."),
		"bi_paste_text":              optionalComputedBool("Allow pasting text in Browser Isolation."),
		"bi_copy_text":               optionalComputedBool("Allow copying text in Browser Isolation."),
		"scan_outbound_emails":       optionalComputedBool("Scan outbound email URLs."),
	}
}

func cloudIntegratedPhishingResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"sensitivity_phishing_high":      optionalComputedInt64("High phishing sensitivity threshold."),
		"sensitivity_untrustworthy_high": optionalComputedInt64("High untrustworthy sensitivity threshold."),
		"scan_outbound_emails":           optionalComputedBool("Scan outbound emails."),
	}
}

func cloudIntegratedImpersonationResourceAttributes() map[string]schema.Attribute {
	status := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Description: description, Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("ENABLED", "DISABLED", "LEARNING")}}
	}
	return map[string]schema.Attribute{
		"code_breaker_status": status("Code Breaker status."),
		"reporting_status":    status("Reporting status."),
		"silencer_status":     status("Silencer status."),
	}
}

func cloudIntegratedAttachmentsResourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"sandbox_enabled":     optionalComputedBool("Enable attachment sandboxing."),
		"unreadable_archives": schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("QUARANTINE", "ALLOW")}},
	}
}

func (r *cloudIntegratedPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *cloudIntegratedPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan cloudIntegratedPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	plan.validate(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateCloudIntegratedPolicy(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Cloud Integrated policy", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetCloudIntegratedPolicy(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Cloud Integrated policy", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudIntegratedPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state cloudIntegratedPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetCloudIntegratedPolicy(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Cloud Integrated policy", err.Error())
		return
	}
	state.fromAPI(ctx, out, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudIntegratedPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan cloudIntegratedPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	plan.validate(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.toAPI(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateCloudIntegratedPolicy(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update Cloud Integrated policy", err.Error())
		return
	}
	updated, err := r.client.GetCloudIntegratedPolicy(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Cloud Integrated policy", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudIntegratedPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state cloudIntegratedPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteCloudIntegratedPolicy(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Cloud Integrated policy", err.Error())
	}
}

func (r *cloudIntegratedPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m cloudIntegratedPolicyModel) validate(diags *diag.Diagnostics) {
	if m.Targets == nil {
		diags.AddError("Missing Cloud Integrated targets", "targets must be configured.")
		return
	}
	for name, target := range map[string]*cloudIntegratedRouteTargetModel{"senders": m.Targets.Senders, "recipients": m.Targets.Recipients} {
		if target != nil && target.Route.ValueString() == "" {
			diags.AddError("Missing Cloud Integrated target route", name+".route must be configured when the target is present.")
		}
	}
}

func (m cloudIntegratedPolicyModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.CloudIntegratedPolicy {
	return client.CloudIntegratedPolicy{
		Name: m.Name.ValueString(), Description: m.Description.ValueString(),
		ProtectionMode: m.ProtectionMode.ValueString(), Targets: m.Targets.toAPI(ctx, diags), Actions: m.Actions.toAPI(), Alerts: m.Alerts.toAPI(), SecurityEngines: m.SecurityEngines.toAPI(),
	}
}

func (m *cloudIntegratedPolicyModel) fromAPI(ctx context.Context, in client.CloudIntegratedPolicy, diags *diag.Diagnostics) {
	if in.PolicyID != "" {
		m.ID = types.StringValue(in.PolicyID)
		m.PolicyID = types.StringValue(in.PolicyID)
	}
	m.AccountID = stringValue(in.AccountID)
	m.Name = stringValue(in.Name)
	m.Description = stringValue(in.Description)
	m.ProtectionMode = stringValue(in.ProtectionMode)
	m.Targets = cloudIntegratedTargetsFromAPI(ctx, in.Targets, diags)
	m.Actions = cloudIntegratedActionsFromAPI(in.Actions)
	m.Alerts = cloudIntegratedAlertsFromAPI(in.Alerts)
	m.SecurityEngines = cloudIntegratedSecurityEnginesFromAPI(in.SecurityEngines)
	m.TargetsSHA256 = canonicalFingerprint(in.Targets)
	m.ActionsSHA256 = canonicalFingerprint(in.Actions)
	m.AlertsSHA256 = canonicalFingerprint(in.Alerts)
	m.SecurityEnginesSHA256 = canonicalFingerprint(in.SecurityEngines)
}

func (m *cloudIntegratedTargetsModel) toAPI(ctx context.Context, diags *diag.Diagnostics) *client.CloudIntegratedTargets {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedTargets{Senders: m.Senders.toAPI(ctx, diags), Recipients: m.Recipients.toAPI(ctx, diags), Exceptions: m.Exceptions.toAPI(ctx, diags), AddressMatch: m.AddressMatch.ValueString()}
}

func (m *cloudIntegratedRouteTargetModel) toAPI(ctx context.Context, diags *diag.Diagnostics) *client.CloudIntegratedRouteTarget {
	if m == nil {
		return nil
	}
	emails := cloudIntegratedStringsFromSet(ctx, m.Emails, diags)
	groups := cloudIntegratedGroupsFromSet(ctx, m.GroupIDs, diags)
	domains := cloudIntegratedStringsFromSet(ctx, m.Domains, diags)
	return &client.CloudIntegratedRouteTarget{Route: m.Route.ValueString(), Emails: emails, Groups: groups, Domains: domains}
}

func (m *cloudIntegratedExceptionModel) toAPI(ctx context.Context, diags *diag.Diagnostics) *client.CloudIntegratedException {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedException{Emails: cloudIntegratedStringsFromSet(ctx, m.Emails, diags), Groups: cloudIntegratedGroupsFromSet(ctx, m.GroupIDs, diags), Domains: cloudIntegratedStringsFromSet(ctx, m.Domains, diags)}
}

func (m *cloudIntegratedActionsModel) toAPI() *client.CloudIntegratedActions {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedActions{Malware: m.Malware.ValueString(), Phishing: m.Phishing.ValueString(), Untrustworthy: m.Untrustworthy.ValueString(), Spam: m.Spam.ValueString()}
}

func (m *cloudIntegratedAlertsModel) toAPI() *client.CloudIntegratedAlerts {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedAlerts{Malware: boolPtr(m.Malware), Phishing: boolPtr(m.Phishing), Untrustworthy: boolPtr(m.Untrustworthy), Spam: boolPtr(m.Spam)}
}

func (m *cloudIntegratedSecurityEnginesModel) toAPI() *client.CloudIntegratedSecurityEngines {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedSecurityEngines{URLClick: m.URLClick.toAPI(), Phishing: m.Phishing.toAPI(), Impersonation: m.Impersonation.toAPI(), Attachments: m.Attachments.toAPI()}
}

func (m *cloudIntegratedURLClickEngineModel) toAPI() *client.CloudIntegratedURLClickEngine {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedURLClickEngine{
		Sensitivity: m.Sensitivity.ValueString(), ScanURLsInAttachment: boolPtr(m.ScanURLsInAttachment), RewriteEnabled: boolPtr(m.RewriteEnabled), RewriteMode: m.RewriteMode.ValueString(),
		ForceSecureConnection: boolPtr(m.ForceSecureConnection), BlockDangerousExtensions: boolPtr(m.BlockDangerousExtensions), UserIdentification: m.UserIdentification.ValueString(),
		BIUnclassifiedURLs: boolPtr(m.BIUnclassifiedURLs), BIAdminViewing: boolPtr(m.BIAdminViewing), BIEnterText: boolPtr(m.BIEnterText), BIPasteText: boolPtr(m.BIPasteText),
		BICopyText: boolPtr(m.BICopyText), ScanOutboundEmails: boolPtr(m.ScanOutboundEmails),
	}
}

func (m *cloudIntegratedPhishingEngineModel) toAPI() *client.CloudIntegratedPhishingEngine {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedPhishingEngine{SensitivityPhishingHigh: cloudIntegratedInt64Ptr(m.SensitivityPhishingHigh), SensitivityUntrustworthyHigh: cloudIntegratedInt64Ptr(m.SensitivityUntrustworthyHigh), ScanOutboundEmails: boolPtr(m.ScanOutboundEmails)}
}

func (m *cloudIntegratedImpersonationEngineModel) toAPI() *client.CloudIntegratedImpersonationEngine {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedImpersonationEngine{CodeBreakerStatus: m.CodeBreakerStatus.ValueString(), ReportingStatus: m.ReportingStatus.ValueString(), SilencerStatus: m.SilencerStatus.ValueString()}
}

func (m *cloudIntegratedAttachmentsEngineModel) toAPI() *client.CloudIntegratedAttachmentsEngine {
	if m == nil {
		return nil
	}
	return &client.CloudIntegratedAttachmentsEngine{SandboxEnabled: boolPtr(m.SandboxEnabled), UnreadableArchives: m.UnreadableArchives.ValueString()}
}

func cloudIntegratedTargetsFromAPI(ctx context.Context, in *client.CloudIntegratedTargets, diags *diag.Diagnostics) *cloudIntegratedTargetsModel {
	if in == nil {
		return nil
	}
	return &cloudIntegratedTargetsModel{Senders: cloudIntegratedRouteTargetFromAPI(ctx, in.Senders, diags), Recipients: cloudIntegratedRouteTargetFromAPI(ctx, in.Recipients, diags), Exceptions: cloudIntegratedExceptionFromAPI(ctx, in.Exceptions, diags), AddressMatch: stringValue(in.AddressMatch)}
}

func cloudIntegratedRouteTargetFromAPI(ctx context.Context, in *client.CloudIntegratedRouteTarget, diags *diag.Diagnostics) *cloudIntegratedRouteTargetModel {
	if in == nil {
		return nil
	}
	return &cloudIntegratedRouteTargetModel{Route: stringValue(in.Route), Emails: cloudIntegratedSetFromStrings(ctx, in.Emails, diags), GroupIDs: cloudIntegratedSetFromGroups(ctx, in.Groups, diags), Domains: cloudIntegratedSetFromStrings(ctx, in.Domains, diags)}
}

func cloudIntegratedExceptionFromAPI(ctx context.Context, in *client.CloudIntegratedException, diags *diag.Diagnostics) *cloudIntegratedExceptionModel {
	if in == nil {
		return nil
	}
	return &cloudIntegratedExceptionModel{Emails: cloudIntegratedSetFromStrings(ctx, in.Emails, diags), GroupIDs: cloudIntegratedSetFromGroups(ctx, in.Groups, diags), Domains: cloudIntegratedSetFromStrings(ctx, in.Domains, diags)}
}

func cloudIntegratedActionsFromAPI(in *client.CloudIntegratedActions) *cloudIntegratedActionsModel {
	if in == nil {
		return nil
	}
	return &cloudIntegratedActionsModel{Malware: stringValue(in.Malware), Phishing: stringValue(in.Phishing), Untrustworthy: stringValue(in.Untrustworthy), Spam: stringValue(in.Spam)}
}

func cloudIntegratedAlertsFromAPI(in *client.CloudIntegratedAlerts) *cloudIntegratedAlertsModel {
	if in == nil {
		return nil
	}
	return &cloudIntegratedAlertsModel{Malware: boolValue(in.Malware), Phishing: boolValue(in.Phishing), Untrustworthy: boolValue(in.Untrustworthy), Spam: boolValue(in.Spam)}
}

func cloudIntegratedSecurityEnginesFromAPI(in *client.CloudIntegratedSecurityEngines) *cloudIntegratedSecurityEnginesModel {
	if in == nil {
		return nil
	}
	out := &cloudIntegratedSecurityEnginesModel{}
	if value := in.URLClick; value != nil {
		out.URLClick = &cloudIntegratedURLClickEngineModel{Sensitivity: stringValue(value.Sensitivity), ScanURLsInAttachment: boolValue(value.ScanURLsInAttachment), RewriteEnabled: boolValue(value.RewriteEnabled), RewriteMode: stringValue(value.RewriteMode), ForceSecureConnection: boolValue(value.ForceSecureConnection), BlockDangerousExtensions: boolValue(value.BlockDangerousExtensions), UserIdentification: stringValue(value.UserIdentification), BIUnclassifiedURLs: boolValue(value.BIUnclassifiedURLs), BIAdminViewing: boolValue(value.BIAdminViewing), BIEnterText: boolValue(value.BIEnterText), BIPasteText: boolValue(value.BIPasteText), BICopyText: boolValue(value.BICopyText), ScanOutboundEmails: boolValue(value.ScanOutboundEmails)}
	}
	if value := in.Phishing; value != nil {
		out.Phishing = &cloudIntegratedPhishingEngineModel{SensitivityPhishingHigh: cloudIntegratedInt64Value(value.SensitivityPhishingHigh), SensitivityUntrustworthyHigh: cloudIntegratedInt64Value(value.SensitivityUntrustworthyHigh), ScanOutboundEmails: boolValue(value.ScanOutboundEmails)}
	}
	if value := in.Impersonation; value != nil {
		out.Impersonation = &cloudIntegratedImpersonationEngineModel{CodeBreakerStatus: stringValue(value.CodeBreakerStatus), ReportingStatus: stringValue(value.ReportingStatus), SilencerStatus: stringValue(value.SilencerStatus)}
	}
	if value := in.Attachments; value != nil {
		out.Attachments = &cloudIntegratedAttachmentsEngineModel{SandboxEnabled: boolValue(value.SandboxEnabled), UnreadableArchives: stringValue(value.UnreadableArchives)}
	}
	return out
}

func cloudIntegratedStringsFromSet(ctx context.Context, value types.Set, diags *diag.Diagnostics) []string {
	items, itemDiags := stringsFromSet(ctx, value)
	diags.Append(itemDiags...)
	sort.Strings(items)
	return items
}

func cloudIntegratedGroupsFromSet(ctx context.Context, value types.Set, diags *diag.Diagnostics) []client.CloudIntegratedGroup {
	ids := cloudIntegratedStringsFromSet(ctx, value, diags)
	groups := make([]client.CloudIntegratedGroup, 0, len(ids))
	for _, id := range ids {
		groups = append(groups, client.CloudIntegratedGroup{ID: id})
	}
	return groups
}

func cloudIntegratedSetFromStrings(ctx context.Context, values []string, diags *diag.Diagnostics) types.Set {
	set, setDiags := setFromStrings(ctx, values)
	diags.Append(setDiags...)
	return set
}

func cloudIntegratedSetFromGroups(ctx context.Context, values []client.CloudIntegratedGroup, diags *diag.Diagnostics) types.Set {
	ids := make([]string, 0, len(values))
	for _, group := range values {
		ids = append(ids, group.ID)
	}
	return cloudIntegratedSetFromStrings(ctx, ids, diags)
}

func cloudIntegratedInt64Ptr(value types.Int64) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueInt64()
	return &result
}

func cloudIntegratedInt64Value(value *int64) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*value)
}

// The default-policy data source uses the same state model and field contract
// as the managed resource, with every nested attribute computed.
func cloudIntegratedDefaultDataSourceAttributes() map[string]dsschema.Attribute {
	return map[string]dsschema.Attribute{
		"id":                      dsID("Stable default-policy data source ID."),
		"policy_id":               dsID("Default policy ID."),
		"account_id":              dsSensitiveString("Cloud Integrated account ID."),
		"name":                    dsString("Policy name."),
		"description":             dsString("Policy description."),
		"protection_mode":         dsString("Protection mode."),
		"targets":                 cloudIntegratedTargetsDataSourceAttribute(),
		"actions":                 cloudIntegratedActionsDataSourceAttribute(),
		"alerts":                  cloudIntegratedAlertsDataSourceAttribute(),
		"security_engines":        cloudIntegratedSecurityEnginesDataSourceAttribute(),
		"targets_sha256":          dsString("Canonical SHA-256 of the typed targets object."),
		"actions_sha256":          dsString("Canonical SHA-256 of the typed actions object."),
		"alerts_sha256":           dsString("Canonical SHA-256 of the typed alerts object."),
		"security_engines_sha256": dsString("Canonical SHA-256 of the typed security-engines object."),
	}
}

func cloudIntegratedTargetsDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"senders": cloudIntegratedRouteTargetDataSourceAttribute(), "recipients": cloudIntegratedRouteTargetDataSourceAttribute(),
		"exceptions": cloudIntegratedExceptionDataSourceAttribute(), "address_match": dsString("Address component used for matching."),
	}}
}

func cloudIntegratedRouteTargetDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"route": dsString("Address route selector."), "emails": cloudIntegratedStringSetDataSource("Email selectors.", true),
		"group_ids": cloudIntegratedStringSetDataSource("Directory group IDs.", false), "domains": cloudIntegratedStringSetDataSource("Domain selectors.", false),
	}}
}

func cloudIntegratedExceptionDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"emails": cloudIntegratedStringSetDataSource("Exception email addresses.", true), "group_ids": cloudIntegratedStringSetDataSource("Exception directory group IDs.", false),
		"domains": cloudIntegratedStringSetDataSource("Exception domains.", false),
	}}
}

func cloudIntegratedStringSetDataSource(description string, sensitive bool) dsschema.SetAttribute {
	return dsschema.SetAttribute{Description: description, Computed: true, Sensitive: sensitive, ElementType: types.StringType}
}

func cloudIntegratedActionsDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"malware": dsString("Malware action."), "phishing": dsString("Phishing action."), "untrustworthy": dsString("Untrustworthy-message action."), "spam": dsString("Spam action."),
	}}
}

func cloudIntegratedAlertsDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"malware": dsBool("Alert on malware."), "phishing": dsBool("Alert on phishing."), "untrustworthy": dsBool("Alert on untrustworthy messages."), "spam": dsBool("Alert on spam."),
	}}
}

func cloudIntegratedSecurityEnginesDataSourceAttribute() dsschema.SingleNestedAttribute {
	return dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
		"url_click": dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
			"sensitivity": dsString("URL sensitivity."), "scan_urls_in_attachment": dsBool("Scan URLs in attachments."), "rewrite_enabled": dsBool("Enable URL rewriting."),
			"rewrite_mode": dsString("URL rewrite mode."), "force_secure_connection": dsBool("Require a secure connection."), "block_dangerous_extensions": dsBool("Block dangerous extensions."),
			"user_identification": dsString("User identification mode."), "bi_unclassified_urls": dsBool("Browser Isolation for unclassified URLs."), "bi_admin_viewing": dsBool("Browser Isolation administrator viewing."),
			"bi_enter_text": dsBool("Browser Isolation text entry."), "bi_paste_text": dsBool("Browser Isolation paste."), "bi_copy_text": dsBool("Browser Isolation copy."), "scan_outbound_emails": dsBool("Scan outbound email URLs."),
		}},
		"phishing": dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
			"sensitivity_phishing_high": dsInt64("High phishing sensitivity threshold."), "sensitivity_untrustworthy_high": dsInt64("High untrustworthy sensitivity threshold."), "scan_outbound_emails": dsBool("Scan outbound emails."),
		}},
		"impersonation": dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
			"code_breaker_status": dsString("Code Breaker status."), "reporting_status": dsString("Reporting status."), "silencer_status": dsString("Silencer status."),
		}},
		"attachments": dsschema.SingleNestedAttribute{Computed: true, Attributes: map[string]dsschema.Attribute{
			"sandbox_enabled": dsBool("Enable attachment sandboxing."), "unreadable_archives": dsString("Unreadable archive action."),
		}},
	}}
}
