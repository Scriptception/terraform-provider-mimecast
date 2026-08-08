package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func dmarcImportIDAndField(ctx context.Context, field string, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(field), req.ID)...)
}

// ---- Delegated domain -----------------------------------------------------

type dmarcDelegatedDomainResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	ManagedDomainID       types.String `tfsdk:"managed_domain_id"`
	Domain                types.String `tfsdk:"domain"`
	Hash                  types.String `tfsdk:"hash"`
	DMARCDelegationStatus types.String `tfsdk:"dmarc_delegation_status"`
	DMARCPolicy           types.String `tfsdk:"dmarc_policy"`
	DKIMDelegationStatus  types.String `tfsdk:"dkim_delegation_status"`
	SPFDelegationStatus   types.String `tfsdk:"spf_delegation_status"`
	Details               types.String `tfsdk:"details"`
}

type dmarcDelegatedDomainResource struct{ client *client.Client }

func NewDMARCDelegatedDomainResource() resource.Resource { return &dmarcDelegatedDomainResource{} }

func (r *dmarcDelegatedDomainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_delegated_domain"
}

func (r *dmarcDelegatedDomainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage DNS delegation for a Mimecast DMARC Analyzer managed domain.", Attributes: map[string]schema.Attribute{
		"id":                      idAttr("Delegated-domain ID. Mimecast uses the managed-domain ID."),
		"managed_domain_id":       requiredReplaceString("Managed-domain ID to delegate."),
		"domain":                  computedString("Delegated domain hostname."),
		"hash":                    computedString("Short identifier used in delegation records."),
		"dmarc_delegation_status": computedString("DMARC delegation status."),
		"dmarc_policy":            computedString("Delegated-domain DMARC policy."),
		"dkim_delegation_status":  computedString("DKIM delegation status."),
		"spf_delegation_status":   computedString("SPF delegation status."),
		"details":                 computedString("Additional delegation details."),
	}}
}

func (r *dmarcDelegatedDomainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcDelegatedDomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcDelegatedDomainResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateManagedDMARCDelegatedDomain(ctx, plan.ManagedDomainID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC delegated domain", err.Error())
		return
	}
	created, err = r.client.GetManagedDMARCDelegatedDomain(ctx, created.ID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC delegated domain", err.Error())
		return
	}
	plan.fromAPI(created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDelegatedDomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcDelegatedDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCDelegatedDomain(ctx, state.ManagedDomainID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC delegated domain", err.Error())
		return
	}
	state.fromAPI(result)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcDelegatedDomainResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// All configurable fields require replacement because Mimecast exposes no update operation.
}

func (r *dmarcDelegatedDomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcDelegatedDomainResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCDelegatedDomain(ctx, state.ManagedDomainID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC delegated domain", err.Error())
	}
}

func (r *dmarcDelegatedDomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	dmarcImportIDAndField(ctx, "managed_domain_id", req, resp)
}

func (model *dmarcDelegatedDomainResourceModel) fromAPI(result client.ManagedDMARCDelegatedDomain) {
	model.ID = stringValue(result.ID)
	model.ManagedDomainID = stringValue(result.ID)
	model.Domain = stringValue(result.Domain)
	model.Hash = stringValue(result.Hash)
	model.DMARCDelegationStatus = stringValue(result.DMARCDelegationStatus)
	model.DMARCPolicy = stringValue(result.DMARCPolicy)
	model.DKIMDelegationStatus = stringValue(result.DKIMDelegationStatus)
	model.SPFDelegationStatus = stringValue(result.SPFDelegationStatus)
	model.Details = stringValue(result.Details)
}

// ---- Domain-group association --------------------------------------------

type dmarcDomainGroupAssociationResourceModel struct {
	ID       types.String `tfsdk:"id"`
	GroupID  types.String `tfsdk:"group_id"`
	DomainID types.String `tfsdk:"domain_id"`
	Domain   types.String `tfsdk:"domain"`
}

type dmarcDomainGroupAssociationResource struct{ client *client.Client }

func NewDMARCDomainGroupAssociationResource() resource.Resource {
	return &dmarcDomainGroupAssociationResource{}
}

func (r *dmarcDomainGroupAssociationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_domain_group_association"
}

func (r *dmarcDomainGroupAssociationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Associate one managed DMARC Analyzer domain with a domain group.", Attributes: map[string]schema.Attribute{
		"id":        idAttr("Composite domain-group and managed-domain ID."),
		"group_id":  requiredReplaceString("DMARC Analyzer domain-group ID."),
		"domain_id": requiredReplaceString("Managed-domain ID to associate."),
		"domain":    computedString("Associated domain hostname."),
	}}
}

func (r *dmarcDomainGroupAssociationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcDomainGroupAssociationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcDomainGroupAssociationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.AddManagedDMARCDomainGroupAssociation(ctx, plan.GroupID.ValueString(), plan.DomainID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC domain-group association", err.Error())
		return
	}
	result, err := r.client.GetManagedDMARCDomainGroupAssociation(ctx, plan.GroupID.ValueString(), plan.DomainID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC domain-group association", err.Error())
		return
	}
	plan.fromAPI(result)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDomainGroupAssociationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcDomainGroupAssociationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCDomainGroupAssociation(ctx, state.GroupID.ValueString(), state.DomainID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC domain-group association", err.Error())
		return
	}
	state.fromAPI(result)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcDomainGroupAssociationResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Both configurable identity fields require replacement.
}

func (r *dmarcDomainGroupAssociationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcDomainGroupAssociationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RemoveManagedDMARCDomainGroupAssociation(ctx, state.GroupID.ValueString(), state.DomainID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC domain-group association", err.Error())
	}
}

func (r *dmarcDomainGroupAssociationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("Invalid DMARC domain-group association import ID", "Use group_id/domain_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("group_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("domain_id"), parts[1])...)
}

func (model *dmarcDomainGroupAssociationResourceModel) fromAPI(result client.DMARCDomainReference) {
	model.ID = types.StringValue(normalizeCompositeID(model.GroupID.ValueString(), model.DomainID.ValueString()))
	model.Domain = stringValue(result.Domain)
}

// ---- DMARC definition -----------------------------------------------------

type dmarcDefinitionResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	DomainID                types.String `tfsdk:"domain_id"`
	PolicyPresetID          types.String `tfsdk:"policy_preset_id"`
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
	RecordHost              types.String `tfsdk:"record_host"`
	RecordName              types.String `tfsdk:"record_name"`
	RecordValue             types.String `tfsdk:"record_value"`
	RecordType              types.String `tfsdk:"record_type"`
	RecordTTL               types.Int64  `tfsdk:"record_ttl"`
	RecordPublished         types.Bool   `tfsdk:"record_published"`
}

type dmarcDefinitionResource struct{ client *client.Client }

func NewDMARCDefinitionResource() resource.Resource { return &dmarcDefinitionResource{} }

func (r *dmarcDefinitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_definition"
}

func (r *dmarcDefinitionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage the DMARC definition for a delegated DMARC Analyzer domain.", Attributes: map[string]schema.Attribute{
		"id":                        idAttr("DMARC definition ID, equal to the delegated domain ID."),
		"domain_id":                 requiredReplaceString("Delegated managed-domain ID."),
		"policy_preset_id":          optionalReplaceString("Policy-preset ID used to create the definition. Required on create; may be omitted when importing because Mimecast does not return it."),
		"version":                   computedString("DMARC version."),
		"policy":                    computedString("DMARC policy."),
		"subdomain_policy":          computedString("DMARC subdomain policy."),
		"rua_addresses":             schema.SetAttribute{Description: "Aggregate-report recipients.", Computed: true, Sensitive: true, ElementType: types.StringType},
		"ruf_addresses":             schema.SetAttribute{Description: "Forensic-report recipients.", Computed: true, Sensitive: true, ElementType: types.StringType},
		"dkim_alignment":            computedString("DKIM alignment mode."),
		"spf_alignment":             computedString("SPF alignment mode."),
		"report_interval":           schema.Int64Attribute{Description: "Aggregate-report interval.", Computed: true},
		"failure_reporting_options": computedString("Failure reporting options."),
		"failure_report_format":     computedString("Failure report format."),
		"percentage":                schema.Int64Attribute{Description: "Policy application percentage.", Computed: true},
		"record_host":               computedString("DMARC redirect record host."),
		"record_name":               computedString("DMARC redirect record name."),
		"record_value":              computedString("DMARC redirect record value."),
		"record_type":               computedString("DMARC redirect record type."),
		"record_ttl":                schema.Int64Attribute{Description: "DMARC redirect record TTL when supplied by Mimecast.", Computed: true},
		"record_published":          schema.BoolAttribute{Description: "Whether the redirect record is published.", Computed: true},
	}}
}

func (r *dmarcDefinitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcDefinitionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("policy_preset_id"), &plan.PolicyPresetID)...)
	if plan.PolicyPresetID.IsNull() || plan.PolicyPresetID.IsUnknown() || plan.PolicyPresetID.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("policy_preset_id"), "Missing DMARC policy preset", "policy_preset_id must be configured when creating a DMARC definition.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.CreateManagedDMARCDefinition(ctx, plan.DomainID.ValueString(), plan.PolicyPresetID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC definition", err.Error())
		return
	}
	result, err := r.client.GetManagedDMARCDefinition(ctx, plan.DomainID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC definition", err.Error())
		return
	}
	plan.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCDefinition(ctx, state.DomainID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC definition", err.Error())
		return
	}
	state.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcDefinitionResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Both configurable attributes require replacement because no update route exists.
}

func (r *dmarcDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCDefinition(ctx, state.DomainID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC definition", err.Error())
	}
}

func (r *dmarcDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	dmarcImportIDAndField(ctx, "domain_id", req, resp)
}

func (model *dmarcDefinitionResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCDefinitionResponse, diags *diag.Diagnostics) {
	model.ID = model.DomainID
	model.Version = stringValue(result.Definition.Version)
	model.Policy = stringValue(result.Definition.Policy)
	model.SubdomainPolicy = stringValue(result.Definition.SubdomainPolicy)
	model.DKIMAlignment = stringValue(result.Definition.DKIMAlignment)
	model.SPFAlignment = stringValue(result.Definition.SPFAlignment)
	model.ReportInterval = dmarcInt64Value(result.Definition.ReportInterval)
	model.FailureReportingOptions = stringValue(result.Definition.FailureReportingOptions)
	model.FailureReportFormat = stringValue(result.Definition.FailureReportFormat)
	model.Percentage = dmarcInt64Value(result.Definition.Percentage)
	var setDiags diag.Diagnostics
	model.RUAAddresses, setDiags = dmarcSetFromPointer(ctx, result.Definition.RUAAddresses)
	diags.Append(setDiags...)
	model.RUFAddresses, setDiags = dmarcSetFromPointer(ctx, result.Definition.RUFAddresses)
	diags.Append(setDiags...)
	model.RecordHost = stringValue(result.Record.Host)
	model.RecordName = stringValue(result.Record.Name)
	model.RecordValue = stringValue(result.Record.Value)
	model.RecordType = stringValue(result.Record.Type)
	model.RecordTTL = dmarcInt64Value(result.Record.TTL.Value)
	model.RecordPublished = boolValue(result.Record.Published)
}

// ---- DKIM definition ------------------------------------------------------

type dmarcDKIMDefinitionResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	DomainID               types.String `tfsdk:"domain_id"`
	SourceID               types.String `tfsdk:"source_id"`
	Version                types.String `tfsdk:"version"`
	Selector               types.String `tfsdk:"selector"`
	RecordType             types.String `tfsdk:"record_type"`
	Hostname               types.String `tfsdk:"hostname"`
	PublicKeyType          types.String `tfsdk:"public_key_type"`
	PublicKeyData          types.String `tfsdk:"public_key_data"`
	ServiceType            types.String `tfsdk:"service_type"`
	Notes                  types.String `tfsdk:"notes"`
	Flags                  types.String `tfsdk:"flags"`
	DelegationRecordName   types.String `tfsdk:"delegation_record_name"`
	DelegationRecordValues types.Set    `tfsdk:"delegation_record_values"`
	DelegationRecordType   types.String `tfsdk:"delegation_record_type"`
	DelegationRecordTTL    types.Int64  `tfsdk:"delegation_record_ttl"`
	DelegationPublished    types.Bool   `tfsdk:"delegation_published"`
}

type dmarcDKIMDefinitionResource struct{ client *client.Client }

func NewDMARCDKIMDefinitionResource() resource.Resource { return &dmarcDKIMDefinitionResource{} }

func (r *dmarcDKIMDefinitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_dkim_definition"
}

func (r *dmarcDKIMDefinitionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage one DKIM definition for a delegated DMARC Analyzer domain.", Attributes: map[string]schema.Attribute{
		"id":        idAttr("Composite domain ID and DKIM selector."),
		"domain_id": requiredReplaceString("Delegated managed-domain ID."),
		"source_id": optionalComputedString("Associated source ID."),
		"version":   optionalComputedString("DKIM version. Required for TXT definitions."),
		"selector":  requiredReplaceString("DKIM selector."),
		"record_type": schema.StringAttribute{Description: "DKIM record type.", Required: true,
			Validators: []validator.String{stringvalidator.OneOf("txt", "cname")}},
		"hostname":                 optionalComputedString("CNAME target. Required for CNAME definitions."),
		"public_key_type":          schema.StringAttribute{Description: "Public-key type for TXT definitions.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("rsa", "ed25519")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"public_key_data":          optionalComputedString("Public-key data for TXT definitions."),
		"service_type":             schema.StringAttribute{Description: "DKIM service type.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("*", "email")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"notes":                    optionalComputedString("DKIM definition notes."),
		"flags":                    schema.StringAttribute{Description: "DKIM flags.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("y", "s", "y:s")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"delegation_record_name":   computedString("DNS delegation record name."),
		"delegation_record_values": schema.SetAttribute{Description: "DNS delegation record values.", Computed: true, ElementType: types.StringType},
		"delegation_record_type":   computedString("DNS delegation record type."),
		"delegation_record_ttl":    schema.Int64Attribute{Description: "DNS delegation record TTL.", Computed: true},
		"delegation_published":     schema.BoolAttribute{Description: "Whether the DNS delegation record is published.", Computed: true},
	}}
}

func (r *dmarcDKIMDefinitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcDKIMDefinitionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config dmarcDKIMDefinitionResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.RecordType.IsNull() || config.RecordType.IsUnknown() {
		return
	}
	validateDMARCDKIMModel(config, &resp.Diagnostics)
}

func validateDMARCDKIMModel(config dmarcDKIMDefinitionResourceModel, diags *diag.Diagnostics) {
	recordType := config.RecordType.ValueString()
	if recordType == "txt" {
		for _, field := range []struct {
			name  string
			value types.String
		}{{"version", config.Version}, {"public_key_type", config.PublicKeyType}, {"public_key_data", config.PublicKeyData}} {
			if field.value.IsUnknown() {
				continue
			}
			if field.value.IsNull() || field.value.ValueString() == "" {
				diags.AddAttributeError(pathRoot(field.name), "Missing TXT DKIM field", fmt.Sprintf("%s is required when record_type is txt.", field.name))
			}
		}
		if dmarcStringConfigured(config.Hostname) {
			diags.AddAttributeError(pathRoot("hostname"), "Invalid TXT DKIM field", "hostname can only be configured when record_type is cname.")
		}
	}
	if recordType == "cname" {
		if !config.Hostname.IsUnknown() && (config.Hostname.IsNull() || config.Hostname.ValueString() == "") {
			diags.AddAttributeError(pathRoot("hostname"), "Missing CNAME DKIM field", "hostname is required when record_type is cname.")
		}
		for _, field := range []struct {
			name       string
			configured bool
		}{{"public_key_type", dmarcStringConfigured(config.PublicKeyType)}, {"public_key_data", dmarcStringConfigured(config.PublicKeyData)}} {
			if field.configured {
				diags.AddAttributeError(pathRoot(field.name), "Invalid CNAME DKIM field", fmt.Sprintf("%s can only be configured when record_type is txt.", field.name))
			}
		}
	}
}

func (r *dmarcDKIMDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcDKIMDefinitionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.CreateManagedDMARCDKIMDefinition(ctx, plan.DomainID.ValueString(), plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC DKIM definition", err.Error())
		return
	}
	if !r.readAfterWrite(ctx, &plan, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDKIMDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcDKIMDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCDKIMDefinition(ctx, state.DomainID.ValueString(), state.Selector.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC DKIM definition", err.Error())
		return
	}
	state.fromAPI(result)
	r.readDetails(ctx, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcDKIMDefinitionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dmarcDKIMDefinitionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateManagedDMARCDKIMDefinition(ctx, plan.DomainID.ValueString(), plan.Selector.ValueString(), plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Unable to update DMARC DKIM definition", err.Error())
		return
	}
	if !r.readAfterWrite(ctx, &plan, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcDKIMDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcDKIMDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCDKIMDefinition(ctx, state.DomainID.ValueString(), state.Selector.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC DKIM definition", err.Error())
	}
}

func (r *dmarcDKIMDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("Invalid DMARC DKIM definition import ID", "Use domain_id/selector.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("domain_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("selector"), parts[1])...)
}

func (r *dmarcDKIMDefinitionResource) readAfterWrite(ctx context.Context, model *dmarcDKIMDefinitionResourceModel, diags *diag.Diagnostics) bool {
	result, err := r.client.GetManagedDMARCDKIMDefinition(ctx, model.DomainID.ValueString(), model.Selector.ValueString())
	if err != nil {
		diags.AddError("Unable to read written DMARC DKIM definition", err.Error())
		return false
	}
	model.fromAPI(result)
	r.readDetails(ctx, model, diags)
	return !diags.HasError()
}

func (r *dmarcDKIMDefinitionResource) readDetails(ctx context.Context, model *dmarcDKIMDefinitionResourceModel, diags *diag.Diagnostics) {
	details, err := r.client.GetManagedDMARCDKIMDelegationDetails(ctx, model.DomainID.ValueString())
	if client.IsNotFound(err) {
		return
	}
	if err != nil {
		diags.AddError("Unable to read DMARC DKIM delegation details", err.Error())
		return
	}
	model.DelegationRecordName = stringValue(details.Record.Name)
	model.DelegationRecordType = stringValue(details.Record.Type)
	model.DelegationRecordTTL = dmarcInt64Value(details.Record.TTL.Value)
	model.DelegationPublished = boolValue(details.Published)
	var setDiags diag.Diagnostics
	model.DelegationRecordValues, setDiags = setFromStrings(ctx, details.Record.Values)
	diags.Append(setDiags...)
}

func (model dmarcDKIMDefinitionResourceModel) toAPI() client.ManagedDMARCDKIMDefinition {
	result := client.ManagedDMARCDKIMDefinition{
		SourceID: model.SourceID.ValueString(), Version: model.Version.ValueString(), Selector: model.Selector.ValueString(),
		RecordType: model.RecordType.ValueString(), Hostname: model.Hostname.ValueString(), ServiceType: model.ServiceType.ValueString(),
		Notes: model.Notes.ValueString(), Flags: model.Flags.ValueString(),
	}
	if dmarcStringConfigured(model.PublicKeyType) || dmarcStringConfigured(model.PublicKeyData) {
		result.PublicKey = &client.DMARCDKIMPublicKey{Type: model.PublicKeyType.ValueString(), Data: model.PublicKeyData.ValueString()}
	}
	return result
}

func (model *dmarcDKIMDefinitionResourceModel) fromAPI(result client.ManagedDMARCDKIMDefinition) {
	model.ID = types.StringValue(normalizeCompositeID(model.DomainID.ValueString(), result.Selector))
	model.SourceID = stringValue(result.SourceID)
	model.Version = stringValue(result.Version)
	model.Selector = stringValue(result.Selector)
	model.RecordType = stringValue(result.RecordType)
	model.Hostname = stringValue(result.Hostname)
	model.ServiceType = stringValue(result.ServiceType)
	model.Notes = stringValue(result.Notes)
	model.Flags = stringValue(result.Flags)
	if result.PublicKey == nil {
		model.PublicKeyType = types.StringNull()
		model.PublicKeyData = types.StringNull()
	} else {
		model.PublicKeyType = stringValue(result.PublicKey.Type)
		model.PublicKeyData = stringValue(result.PublicKey.Data)
	}
}

// ---- SPF definition -------------------------------------------------------

var dmarcSPFTermObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"type": types.StringType, "source_id": types.StringType, "label": types.StringType, "target": types.StringType,
	"cidr_ipv4": types.Int64Type, "cidr_ipv6": types.Int64Type,
}}

type dmarcSPFTermModel struct {
	Type     types.String `tfsdk:"type"`
	SourceID types.String `tfsdk:"source_id"`
	Label    types.String `tfsdk:"label"`
	Target   types.String `tfsdk:"target"`
	CIDRIPv4 types.Int64  `tfsdk:"cidr_ipv4"`
	CIDRIPv6 types.Int64  `tfsdk:"cidr_ipv6"`
}

type dmarcSPFDefinitionResourceModel struct {
	ID              types.String `tfsdk:"id"`
	DomainID        types.String `tfsdk:"domain_id"`
	Version         types.String `tfsdk:"version"`
	Terms           types.List   `tfsdk:"terms"`
	AllQualifier    types.String `tfsdk:"all_qualifier"`
	RecordName      types.String `tfsdk:"record_name"`
	RecordValue     types.String `tfsdk:"record_value"`
	RecordType      types.String `tfsdk:"record_type"`
	RecordTTL       types.Int64  `tfsdk:"record_ttl"`
	Published       types.Bool   `tfsdk:"published"`
	NormalizedValue types.String `tfsdk:"normalized_value"`
	CompressedValue types.String `tfsdk:"compressed_value"`
}

type dmarcSPFDefinitionResource struct{ client *client.Client }

func NewDMARCSPFDefinitionResource() resource.Resource { return &dmarcSPFDefinitionResource{} }

func (r *dmarcSPFDefinitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_spf_definition"
}

func (r *dmarcSPFDefinitionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage the SPF definition for a delegated DMARC Analyzer domain.", Attributes: map[string]schema.Attribute{
		"id":        idAttr("SPF definition ID, equal to the delegated domain ID."),
		"domain_id": requiredReplaceString("Delegated managed-domain ID."),
		"version":   requiredString("SPF version, such as v=spf1."),
		"all_qualifier": schema.StringAttribute{Description: "SPF all mechanism qualifier.", Required: true,
			Validators: []validator.String{stringvalidator.OneOf("-all", "~all")}},
		"terms": schema.ListNestedAttribute{
			Description: "Ordered SPF terms.", Optional: true, PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
			NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
				"type":      schema.StringAttribute{Description: "SPF term type.", Required: true, Validators: []validator.String{stringvalidator.OneOf("a", "exists", "include", "ip4", "ip6", "mx")}},
				"source_id": schema.StringAttribute{Description: "Associated source ID.", Optional: true},
				"label":     schema.StringAttribute{Description: "SPF term label.", Optional: true},
				"target":    requiredString("SPF term target."),
				"cidr_ipv4": schema.Int64Attribute{Description: "IPv4 CIDR prefix length.", Optional: true, Validators: []validator.Int64{int64validator.Between(0, 32)}},
				"cidr_ipv6": schema.Int64Attribute{Description: "IPv6 CIDR prefix length.", Optional: true, Validators: []validator.Int64{int64validator.Between(0, 128)}},
			}},
		},
		"record_name":      computedString("Published SPF record name."),
		"record_value":     computedString("Published SPF record value."),
		"record_type":      computedString("Published SPF record type."),
		"record_ttl":       schema.Int64Attribute{Description: "Published SPF record TTL.", Computed: true},
		"published":        schema.BoolAttribute{Description: "Whether the SPF record is published.", Computed: true},
		"normalized_value": computedString("Normalized uncompressed SPF record."),
		"compressed_value": computedString("Compressed SPF record."),
	}}
}

func (r *dmarcSPFDefinitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcSPFDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.write(ctx, req.Plan, &resp.State, &resp.Diagnostics)
}

func (r *dmarcSPFDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcSPFDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	definition, err := r.client.GetManagedDMARCSPFDefinition(ctx, state.DomainID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC SPF definition", err.Error())
		return
	}
	state.fromAPI(ctx, definition, &resp.Diagnostics)
	r.readDetails(ctx, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcSPFDefinitionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.write(ctx, req.Plan, &resp.State, &resp.Diagnostics)
}

type dmarcPlanGetter interface {
	Get(context.Context, any) diag.Diagnostics
}

type dmarcStateSetter interface {
	Set(context.Context, any) diag.Diagnostics
}

func (r *dmarcSPFDefinitionResource) write(ctx context.Context, plan dmarcPlanGetter, state dmarcStateSetter, diags *diag.Diagnostics) {
	var model dmarcSPFDefinitionResourceModel
	diags.Append(plan.Get(ctx, &model)...)
	request := model.toAPI(ctx, diags)
	if diags.HasError() {
		return
	}
	if err := r.client.PutManagedDMARCSPFDefinition(ctx, model.DomainID.ValueString(), request); err != nil {
		diags.AddError("Unable to write DMARC SPF definition", err.Error())
		return
	}
	definition, err := r.client.GetManagedDMARCSPFDefinition(ctx, model.DomainID.ValueString())
	if err != nil {
		diags.AddError("Unable to read written DMARC SPF definition", err.Error())
		return
	}
	model.fromAPI(ctx, definition, diags)
	r.readDetails(ctx, &model, diags)
	diags.Append(state.Set(ctx, &model)...)
}

func (r *dmarcSPFDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcSPFDefinitionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCSPFDefinition(ctx, state.DomainID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC SPF definition", err.Error())
	}
}

func (r *dmarcSPFDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	dmarcImportIDAndField(ctx, "domain_id", req, resp)
}

func (r *dmarcSPFDefinitionResource) readDetails(ctx context.Context, model *dmarcSPFDefinitionResourceModel, diags *diag.Diagnostics) {
	details, err := r.client.GetManagedDMARCSPFDetails(ctx, model.DomainID.ValueString())
	if client.IsNotFound(err) {
		return
	}
	if err != nil {
		diags.AddError("Unable to read DMARC SPF details", err.Error())
		return
	}
	model.RecordName = stringValue(details.Definition.Record.Name)
	model.RecordValue = stringValue(details.Definition.Record.Value)
	model.RecordType = stringValue(details.Definition.Record.Type)
	model.RecordTTL = dmarcInt64Value(details.Definition.Record.TTL.Value)
	model.Published = boolValue(details.Definition.Published)
	model.NormalizedValue = stringValue(details.Definition.Normalized)
	model.CompressedValue = stringValue(details.Definition.Compressed)
}

func (model dmarcSPFDefinitionResourceModel) toAPI(ctx context.Context, diags *diag.Diagnostics) client.ManagedDMARCSPFDefinition {
	terms := make([]dmarcSPFTermModel, 0)
	if !model.Terms.IsNull() && !model.Terms.IsUnknown() {
		diags.Append(model.Terms.ElementsAs(ctx, &terms, false)...)
	}
	apiTerms := make([]client.ManagedDMARCSPFTerm, 0, len(terms))
	for _, term := range terms {
		apiTerms = append(apiTerms, client.ManagedDMARCSPFTerm{
			Type: term.Type.ValueString(), SourceID: term.SourceID.ValueString(), Label: term.Label.ValueString(), Target: term.Target.ValueString(),
			CIDRIPv4: dmarcInt64Pointer(term.CIDRIPv4), CIDRIPv6: dmarcInt64Pointer(term.CIDRIPv6),
		})
	}
	return client.ManagedDMARCSPFDefinition{Version: model.Version.ValueString(), Terms: apiTerms, AllQualifier: model.AllQualifier.ValueString()}
}

func (model *dmarcSPFDefinitionResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCSPFDefinition, diags *diag.Diagnostics) {
	model.ID = model.DomainID
	model.Version = stringValue(result.Version)
	model.AllQualifier = stringValue(result.AllQualifier)
	terms := make([]dmarcSPFTermModel, 0, len(result.Terms))
	for _, term := range result.Terms {
		terms = append(terms, dmarcSPFTermModel{
			Type: stringValue(term.Type), SourceID: stringValue(term.SourceID), Label: stringValue(term.Label), Target: stringValue(term.Target),
			CIDRIPv4: dmarcInt64Value(term.CIDRIPv4), CIDRIPv6: dmarcInt64Value(term.CIDRIPv6),
		})
	}
	if result.Terms == nil {
		model.Terms = types.ListNull(dmarcSPFTermObjectType)
		return
	}
	var termDiags diag.Diagnostics
	model.Terms, termDiags = types.ListValueFrom(ctx, dmarcSPFTermObjectType, terms)
	diags.Append(termDiags...)
}

type dmarcVendorDataSourceItemModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Instructions  types.String `tfsdk:"instructions"`
	DKIMSelectors types.Set    `tfsdk:"dkim_selectors"`
	SPFIncludes   types.Set    `tfsdk:"spf_includes"`
	Hostnames     types.Set    `tfsdk:"hostnames"`
	Category      types.String `tfsdk:"category"`
	Status        types.String `tfsdk:"status"`
}

type dmarcVendorsDataSourceModel struct {
	ID       types.String                     `tfsdk:"id"`
	VendorID types.String                     `tfsdk:"vendor_id"`
	Items    []dmarcVendorDataSourceItemModel `tfsdk:"items"`
}

type dmarcVendorsDataSource struct{ client *client.Client }

func NewDMARCVendorsDataSource() datasource.DataSource { return &dmarcVendorsDataSource{} }

func (d *dmarcVendorsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_vendors"
}

func (d *dmarcVendorsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	itemAttributes := map[string]dsschema.Attribute{
		"id":             dsschema.StringAttribute{Description: "Vendor ID.", Computed: true},
		"name":           dsschema.StringAttribute{Description: "Vendor name.", Computed: true},
		"instructions":   dsschema.StringAttribute{Description: "Vendor configuration instructions URL.", Computed: true},
		"dkim_selectors": dsschema.SetAttribute{Description: "Vendor DKIM selectors.", Computed: true, ElementType: types.StringType},
		"spf_includes":   dsschema.SetAttribute{Description: "Vendor SPF include terms.", Computed: true, ElementType: types.StringType},
		"hostnames":      dsschema.SetAttribute{Description: "Vendor hostnames.", Computed: true, ElementType: types.StringType},
		"category":       dsschema.StringAttribute{Description: "Vendor category.", Computed: true},
		"status":         dsschema.StringAttribute{Description: "Vendor association status.", Computed: true},
	}
	resp.Schema = dsschema.Schema{Description: "Read the DMARC Analyzer vendor catalogue or one vendor by ID.", Attributes: map[string]dsschema.Attribute{
		"id":        dsschema.StringAttribute{Description: "Stable DMARC vendor inventory ID.", Computed: true},
		"vendor_id": dsschema.StringAttribute{Description: "Optional vendor ID for a detail lookup. Omit to list every vendor with cursor pagination.", Optional: true},
		"items":     dsschema.ListNestedAttribute{Computed: true, NestedObject: dsschema.NestedAttributeObject{Attributes: itemAttributes}},
	}}
}

func (d *dmarcVendorsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.client = apiClient
}

func (d *dmarcVendorsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Mimecast API client is unavailable.")
		return
	}
	var config dmarcVendorsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vendors := make([]client.ManagedDMARCVendor, 0)
	stateID := "dmarc_vendors"
	if !config.VendorID.IsNull() && !config.VendorID.IsUnknown() && config.VendorID.ValueString() != "" {
		vendor, err := d.client.GetManagedDMARCVendor(ctx, config.VendorID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC vendor", err.Error())
			return
		}
		vendors = append(vendors, vendor)
		stateID = config.VendorID.ValueString()
	} else {
		var err error
		vendors, err = d.client.ListManagedDMARCVendors(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DMARC vendors", err.Error())
			return
		}
	}
	items := make([]dmarcVendorDataSourceItemModel, 0, len(vendors))
	for _, vendor := range vendors {
		dkimSelectors, dkimDiags := setFromStrings(ctx, vendor.DKIMSelectors)
		spfIncludes, spfDiags := setFromStrings(ctx, vendor.SPFInclude)
		hostnames, hostnameDiags := setFromStrings(ctx, vendor.Hostnames)
		resp.Diagnostics.Append(dkimDiags...)
		resp.Diagnostics.Append(spfDiags...)
		resp.Diagnostics.Append(hostnameDiags...)
		items = append(items, dmarcVendorDataSourceItemModel{
			ID: stringValue(vendor.ID), Name: stringValue(vendor.Name), Instructions: stringValue(vendor.Instructions),
			DKIMSelectors: dkimSelectors, SPFIncludes: spfIncludes, Hostnames: hostnames,
			Category: stringValue(vendor.Category), Status: stringValue(vendor.Status),
		})
	}
	config.ID = types.StringValue(stateID)
	config.Items = items
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// ---- DMARC Analyzer user --------------------------------------------------

type dmarcUserResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	UserName               types.String `tfsdk:"user_name"`
	UserEmail              types.String `tfsdk:"user_email"`
	UserPermission         types.String `tfsdk:"user_permission"`
	AllowedGroupIDs        types.Set    `tfsdk:"allowed_group_ids"`
	AggregateReports       types.Bool   `tfsdk:"aggregate_reports"`
	AlertsAndNotifications types.Bool   `tfsdk:"alerts_and_notifications"`
	DNSDelegation          types.Bool   `tfsdk:"dns_delegation"`
	DNSChecker             types.Bool   `tfsdk:"dns_checker"`
	DNSGenerator           types.Bool   `tfsdk:"dns_generator"`
	DomainManagement       types.Bool   `tfsdk:"domain_management"`
	EncryptionPGPKey       types.Bool   `tfsdk:"encryption_pgp_key"`
	ForensicReports        types.Bool   `tfsdk:"forensic_reports"`
	Reporting              types.Bool   `tfsdk:"reporting"`
	TaskManager            types.Bool   `tfsdk:"task_manager"`
	Timeline               types.Bool   `tfsdk:"timeline"`
	TLSReports             types.Bool   `tfsdk:"tls_reports"`
	UserManagement         types.Bool   `tfsdk:"user_management"`
	VendorManagement       types.Bool   `tfsdk:"vendor_management"`
}

type dmarcUserResource struct{ client *client.Client }

func NewDMARCUserResource() resource.Resource { return &dmarcUserResource{} }

func (r *dmarcUserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc_user"
}

func dmarcUserFeatureAttribute(description string) schema.BoolAttribute {
	return schema.BoolAttribute{Description: description, Optional: true, Computed: true}
}

func (r *dmarcUserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast DMARC Analyzer user.", Attributes: map[string]schema.Attribute{
		"id":                       idAttr("DMARC Analyzer user ID."),
		"user_name":                schema.StringAttribute{Description: "User name. Mimecast does not expose it in the update request.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.LengthAtMost(100)}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
		"user_email":               schema.StringAttribute{Description: "User email address. Mimecast does not expose it in the update request.", Required: true, Sensitive: true, Validators: []validator.String{stringvalidator.LengthAtMost(400), dmarcEmailValidator{}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"user_permission":          schema.StringAttribute{Description: "User permission level.", Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("none", "full", "limited")}, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"allowed_group_ids":        schema.SetAttribute{Description: "Domain-group IDs the user may access.", Optional: true, Computed: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtMost(10)}, PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()}},
		"aggregate_reports":        dmarcUserFeatureAttribute("Whether the user can access aggregate reports."),
		"alerts_and_notifications": dmarcUserFeatureAttribute("Whether the user can access alerts and notifications."),
		"dns_delegation":           dmarcUserFeatureAttribute("Whether the user can access DNS delegation."),
		"dns_checker":              dmarcUserFeatureAttribute("Whether the user can access the DNS checker."),
		"dns_generator":            dmarcUserFeatureAttribute("Whether the user can access the DNS generator."),
		"domain_management":        dmarcUserFeatureAttribute("Whether the user can access domain management."),
		"encryption_pgp_key":       dmarcUserFeatureAttribute("Whether the user can access encryption PGP keys."),
		"forensic_reports":         dmarcUserFeatureAttribute("Whether the user can access forensic reports."),
		"reporting":                dmarcUserFeatureAttribute("Whether the user can access reporting."),
		"task_manager":             dmarcUserFeatureAttribute("Whether the user can access task management."),
		"timeline":                 dmarcUserFeatureAttribute("Whether the user can access the timeline."),
		"tls_reports":              dmarcUserFeatureAttribute("Whether the user can access SMTP TLS reports."),
		"user_management":          dmarcUserFeatureAttribute("Whether the user can access user management."),
		"vendor_management":        dmarcUserFeatureAttribute("Whether the user can access vendor management."),
	}}
}

func (r *dmarcUserResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *dmarcUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dmarcUserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateManagedDMARCUser(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DMARC Analyzer user", err.Error())
		return
	}
	if created.ID == "" {
		resp.Diagnostics.AddError("Unable to create DMARC Analyzer user", "Mimecast returned no user ID.")
		return
	}
	created, err = r.client.GetManagedDMARCUser(ctx, created.ID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DMARC Analyzer user", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dmarcUserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.GetManagedDMARCUser(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DMARC Analyzer user", err.Error())
		return
	}
	state.fromAPI(ctx, result, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dmarcUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dmarcUserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	request := plan.toAPI(ctx, &resp.Diagnostics, false)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateManagedDMARCUser(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update DMARC Analyzer user", err.Error())
		return
	}
	updated, err := r.client.GetManagedDMARCUser(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated DMARC Analyzer user", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *dmarcUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dmarcUserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManagedDMARCUser(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DMARC Analyzer user", err.Error())
	}
}

func (r *dmarcUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (model dmarcUserResourceModel) toAPI(ctx context.Context, diags *diag.Diagnostics, includeIdentity bool) client.ManagedDMARCUserRequest {
	allowedGroups, groupDiags := dmarcOptionalStringSetPointer(ctx, model.AllowedGroupIDs)
	diags.Append(groupDiags...)
	features := &client.ManagedDMARCUserFeatures{
		AggregateReports: boolPtr(model.AggregateReports), AlertsAndNotifications: boolPtr(model.AlertsAndNotifications),
		DNSDelegation: boolPtr(model.DNSDelegation), DNSChecker: boolPtr(model.DNSChecker), DNSGenerator: boolPtr(model.DNSGenerator),
		DomainManagement: boolPtr(model.DomainManagement), EncryptionPGPKey: boolPtr(model.EncryptionPGPKey), ForensicReports: boolPtr(model.ForensicReports),
		Reporting: boolPtr(model.Reporting), TaskManager: boolPtr(model.TaskManager), Timeline: boolPtr(model.Timeline), TLSReports: boolPtr(model.TLSReports),
		UserManagement: boolPtr(model.UserManagement), VendorManagement: boolPtr(model.VendorManagement),
	}
	if client.DMARCUserFeaturesEmpty(features) {
		features = nil
	}
	request := client.ManagedDMARCUserRequest{UserPermission: model.UserPermission.ValueString(), AllowedGroups: allowedGroups, Features: features}
	if includeIdentity {
		request.UserName = model.UserName.ValueString()
		request.UserEmail = model.UserEmail.ValueString()
	}
	return request
}

func (model *dmarcUserResourceModel) fromAPI(ctx context.Context, result client.ManagedDMARCUser, diags *diag.Diagnostics) {
	model.ID = stringValue(result.ID)
	model.UserName = stringValue(result.UserName)
	model.UserEmail = stringValue(result.UserEmail)
	model.UserPermission = stringValue(result.UserPermission)
	groupIDs := make([]string, 0, len(result.AllowedGroups))
	for _, group := range result.AllowedGroups {
		if group.ID != "" {
			groupIDs = append(groupIDs, group.ID)
		}
	}
	sort.Strings(groupIDs)
	var setDiags diag.Diagnostics
	model.AllowedGroupIDs, setDiags = setFromStrings(ctx, groupIDs)
	diags.Append(setDiags...)
	if result.Features == nil {
		model.clearFeatures()
		return
	}
	features := result.Features
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

func (model *dmarcUserResourceModel) clearFeatures() {
	model.AggregateReports = types.BoolNull()
	model.AlertsAndNotifications = types.BoolNull()
	model.DNSDelegation = types.BoolNull()
	model.DNSChecker = types.BoolNull()
	model.DNSGenerator = types.BoolNull()
	model.DomainManagement = types.BoolNull()
	model.EncryptionPGPKey = types.BoolNull()
	model.ForensicReports = types.BoolNull()
	model.Reporting = types.BoolNull()
	model.TaskManager = types.BoolNull()
	model.Timeline = types.BoolNull()
	model.TLSReports = types.BoolNull()
	model.UserManagement = types.BoolNull()
	model.VendorManagement = types.BoolNull()
}

var (
	_ resource.Resource                   = (*dmarcDelegatedDomainResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcDelegatedDomainResource)(nil)
	_ resource.Resource                   = (*dmarcDomainGroupAssociationResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcDomainGroupAssociationResource)(nil)
	_ resource.Resource                   = (*dmarcDefinitionResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcDefinitionResource)(nil)
	_ resource.Resource                   = (*dmarcDKIMDefinitionResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcDKIMDefinitionResource)(nil)
	_ resource.ResourceWithValidateConfig = (*dmarcDKIMDefinitionResource)(nil)
	_ resource.Resource                   = (*dmarcSPFDefinitionResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcSPFDefinitionResource)(nil)
	_ resource.Resource                   = (*dmarcUserResource)(nil)
	_ resource.ResourceWithImportState    = (*dmarcUserResource)(nil)
)
