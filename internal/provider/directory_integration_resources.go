package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

var directoryMaxUnlinkValues = []string{
	"0", "10", "20", "50", "100", "300", "500", "1,000", "2,000", "5,000", "10,000", "50,000", "100,000", "unlimited",
}

type activeDirectoryIntegrationModel struct {
	ID                          types.String `tfsdk:"id"`
	Description                 types.String `tfsdk:"description"`
	Info                        types.String `tfsdk:"info"`
	Domains                     types.List   `tfsdk:"domains"`
	Hostname                    types.String `tfsdk:"hostname"`
	AlternateHostname           types.String `tfsdk:"alternate_hostname"`
	Port                        types.Int64  `tfsdk:"port"`
	UserDN                      types.String `tfsdk:"user_dn"`
	PasswordWO                  types.String `tfsdk:"password_wo"`
	PasswordWOVersion           types.Int64  `tfsdk:"password_wo_version"`
	RootDN                      types.String `tfsdk:"root_dn"`
	EncryptionMode              types.String `tfsdk:"encryption_mode"`
	AcknowledgeDisabledAccounts types.Bool   `tfsdk:"acknowledge_disabled_accounts"`
	Enabled                     types.Bool   `tfsdk:"enabled"`
	MaxUnlink                   types.String `tfsdk:"max_unlink"`
	SyncContacts                types.Bool   `tfsdk:"sync_contacts"`
	DeleteUsers                 types.Bool   `tfsdk:"delete_users"`
	Status                      types.String `tfsdk:"status"`
	LastSyncDateTime            types.String `tfsdk:"last_sync_date_time"`
	SyncRunning                 types.Bool   `tfsdk:"sync_running"`
}

type activeDirectoryIntegrationResource struct{ client *client.Client }

func NewActiveDirectoryIntegrationResource() resource.Resource {
	return &activeDirectoryIntegrationResource{}
}

func (r *activeDirectoryIntegrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_active_directory_integration"
}

func (r *activeDirectoryIntegrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage a Mimecast Active Directory integration.",
		Attributes: map[string]schema.Attribute{
			"id":                            idAttr("Mimecast Active Directory integration ID."),
			"description":                   directoryRequiredString("Integration description.", 120),
			"info":                          directoryOptionalComputedString("Additional integration information.", 240),
			"domains":                       optionalComputedStringList("Domains synchronised by the integration."),
			"hostname":                      requiredString("Active Directory server IP address or hostname."),
			"alternate_hostname":            requiredString("Alternate Active Directory server IP address or hostname."),
			"port":                          directoryOptionalComputedPort(),
			"user_dn":                       requiredString("Distinguished name used to connect to Active Directory."),
			"password_wo":                   directoryWriteOnlyString("Active Directory password. Write-only; increment password_wo_version when changing it."),
			"password_wo_version":           directoryWriteOnlyVersion("Version trigger for password_wo. Increment this when changing the password."),
			"root_dn":                       requiredString("Root distinguished name searched by the integration."),
			"encryption_mode":               directoryOptionalComputedEnum("Directory encryption mode.", "relaxed", "strict", "none"),
			"acknowledge_disabled_accounts": optionalComputedBool("Whether disabled Active Directory accounts are acknowledged."),
			"enabled":                       optionalComputedBool("Whether the integration is enabled."),
			"max_unlink":                    directoryMaxUnlinkAttribute(),
			"sync_contacts":                 optionalComputedBool("Whether contacts are synchronised."),
			"delete_users":                  optionalComputedBool("Whether users removed from the directory are deleted from Mimecast."),
			"status":                        computedString("Integration status."),
			"last_sync_date_time":           computedString("Time of the last directory synchronisation."),
			"sync_running":                  schema.BoolAttribute{Description: "Whether a directory synchronisation is running.", Computed: true},
		},
	}
}

func (r *activeDirectoryIntegrationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *activeDirectoryIntegrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan activeDirectoryIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("password_wo"), &plan.PasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.createRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateActiveDirectoryIntegration(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Active Directory integration", err.Error())
		return
	}

	created, err := r.client.GetActiveDirectoryIntegration(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Active Directory integration", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	plan.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *activeDirectoryIntegrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state activeDirectoryIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := r.client.GetActiveDirectoryIntegration(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Active Directory integration", err.Error())
		return
	}
	state.fromAPI(ctx, out, &resp.Diagnostics)
	state.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *activeDirectoryIntegrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan activeDirectoryIntegrationModel
	var state activeDirectoryIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("password_wo"), &plan.PasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.updateRequest(ctx, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateActiveDirectoryIntegration(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update Active Directory integration", err.Error())
		return
	}
	updated, err := r.client.GetActiveDirectoryIntegration(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Active Directory integration", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	plan.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *activeDirectoryIntegrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state activeDirectoryIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteActiveDirectoryIntegration(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Active Directory integration", err.Error())
	}
}

func (r *activeDirectoryIntegrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m activeDirectoryIntegrationModel) createRequest(ctx context.Context, diags *diag.Diagnostics) client.ActiveDirectoryIntegrationCreateRequest {
	password := requiredWriteOnlyValue("password_wo", m.PasswordWO, diags)
	domains, domainDiags := directoryStringListPointer(ctx, m.Domains)
	diags.Append(domainDiags...)
	return client.ActiveDirectoryIntegrationCreateRequest{
		Description:                 m.Description.ValueString(),
		Info:                        directoryStringPointer(m.Info),
		Domains:                     domains,
		Hostname:                    m.Hostname.ValueString(),
		AlternateHostname:           m.AlternateHostname.ValueString(),
		Port:                        directoryInt64Pointer(m.Port),
		UserDN:                      m.UserDN.ValueString(),
		Password:                    password,
		RootDN:                      m.RootDN.ValueString(),
		EncryptionMode:              directoryStringPointer(m.EncryptionMode),
		AcknowledgeDisabledAccounts: directoryBoolPointer(m.AcknowledgeDisabledAccounts),
		Enabled:                     directoryBoolPointer(m.Enabled),
		MaxUnlink:                   directoryStringPointer(m.MaxUnlink),
		SyncContacts:                directoryBoolPointer(m.SyncContacts),
		DeleteUsers:                 directoryBoolPointer(m.DeleteUsers),
	}
}

func (m activeDirectoryIntegrationModel) updateRequest(ctx context.Context, prior activeDirectoryIntegrationModel, diags *diag.Diagnostics) client.ActiveDirectoryIntegrationUpdateRequest {
	request := client.ActiveDirectoryIntegrationUpdateRequest{}
	request.Description = changedDirectoryString(m.Description, prior.Description)
	request.Info = changedDirectoryString(m.Info, prior.Info)
	request.Domains = changedDirectoryStringList(ctx, m.Domains, prior.Domains, diags)
	request.Hostname = changedDirectoryString(m.Hostname, prior.Hostname)
	request.AlternateHostname = changedDirectoryString(m.AlternateHostname, prior.AlternateHostname)
	request.Port = changedDirectoryInt64(m.Port, prior.Port)
	request.UserDN = changedDirectoryString(m.UserDN, prior.UserDN)
	request.RootDN = changedDirectoryString(m.RootDN, prior.RootDN)
	request.EncryptionMode = changedDirectoryString(m.EncryptionMode, prior.EncryptionMode)
	request.AcknowledgeDisabledAccounts = changedDirectoryBool(m.AcknowledgeDisabledAccounts, prior.AcknowledgeDisabledAccounts)
	request.Enabled = changedDirectoryBool(m.Enabled, prior.Enabled)
	request.MaxUnlink = changedDirectoryString(m.MaxUnlink, prior.MaxUnlink)
	request.SyncContacts = changedDirectoryBool(m.SyncContacts, prior.SyncContacts)
	request.DeleteUsers = changedDirectoryBool(m.DeleteUsers, prior.DeleteUsers)
	if directoryVersionChanged(m.PasswordWOVersion, prior.PasswordWOVersion) {
		password := requiredWriteOnlyValue("password_wo", m.PasswordWO, diags)
		if !diags.HasError() {
			request.Password = &password
		}
	}
	return request
}

func (m *activeDirectoryIntegrationModel) fromAPI(ctx context.Context, in client.ActiveDirectoryIntegration, diags *diag.Diagnostics) {
	setDirectoryString(&m.Description, in.Description)
	setDirectoryString(&m.Info, in.Info)
	setDirectoryStringList(ctx, &m.Domains, in.Domains, diags)
	setDirectoryString(&m.Hostname, in.Hostname)
	setDirectoryString(&m.AlternateHostname, in.AlternateHostname)
	setDirectoryInt64(&m.Port, in.Port)
	setDirectoryString(&m.UserDN, in.UserDN)
	setDirectoryString(&m.RootDN, in.RootDN)
	setDirectoryString(&m.EncryptionMode, in.EncryptionMode)
	setDirectoryBool(&m.AcknowledgeDisabledAccounts, in.AcknowledgeDisabledAccounts)
	setDirectoryBool(&m.Enabled, in.Enabled)
	setDirectoryUnlinkLimit(&m.MaxUnlink, in.MaxUnlink)
	setDirectoryBool(&m.SyncContacts, in.SyncContacts)
	setDirectoryBool(&m.DeleteUsers, in.DeleteUsers)
	setDirectoryString(&m.Status, in.Status)
	setDirectoryString(&m.LastSyncDateTime, in.LastSyncDateTime)
	setDirectoryBool(&m.SyncRunning, in.SyncRunning)
}

type googleDirectoryIntegrationModel struct {
	ID                          types.String `tfsdk:"id"`
	Enabled                     types.Bool   `tfsdk:"enabled"`
	Description                 types.String `tfsdk:"description"`
	Info                        types.String `tfsdk:"info"`
	Domains                     types.List   `tfsdk:"domains"`
	MaxUnlink                   types.String `tfsdk:"max_unlink"`
	DeleteUsers                 types.Bool   `tfsdk:"delete_users"`
	AcknowledgeDisabledAccounts types.Bool   `tfsdk:"acknowledge_disabled_accounts"`
	User                        types.String `tfsdk:"user"`
	ServiceAccountKeyWO         types.String `tfsdk:"service_account_key_wo"`
	ServiceAccountKeyWOVersion  types.Int64  `tfsdk:"service_account_key_wo_version"`
	LastSyncDateTime            types.String `tfsdk:"last_sync_date_time"`
	Status                      types.String `tfsdk:"status"`
	SyncRunning                 types.Bool   `tfsdk:"sync_running"`
}

type googleDirectoryIntegrationResource struct{ client *client.Client }

func NewGoogleWorkspaceDirectoryIntegrationResource() resource.Resource {
	return &googleDirectoryIntegrationResource{}
}

func (r *googleDirectoryIntegrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_google_workspace_directory_integration"
}

func (r *googleDirectoryIntegrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage a Mimecast Google Workspace directory integration.",
		Attributes: map[string]schema.Attribute{
			"id":                             idAttr("Mimecast Google Workspace directory integration ID."),
			"enabled":                        optionalComputedBool("Whether the integration is enabled."),
			"description":                    directoryRequiredString("Integration description.", 120),
			"info":                           directoryOptionalComputedString("Additional integration information.", 240),
			"domains":                        optionalComputedStringList("Domains synchronised by the integration."),
			"max_unlink":                     directoryMaxUnlinkAttribute(),
			"delete_users":                   optionalComputedBool("Whether users removed from the directory are deleted from Mimecast."),
			"acknowledge_disabled_accounts":  optionalComputedBool("Whether disabled directory accounts are acknowledged."),
			"user":                           requiredString("Google Workspace user email address used by the service account."),
			"service_account_key_wo":         directoryWriteOnlyString("Google service-account JSON key. Write-only; increment service_account_key_wo_version when changing it."),
			"service_account_key_wo_version": directoryWriteOnlyVersion("Version trigger for service_account_key_wo. Increment this when changing the key."),
			"last_sync_date_time":            computedString("Time of the last directory synchronisation."),
			"status":                         computedString("Integration status."),
			"sync_running":                   schema.BoolAttribute{Description: "Whether a directory synchronisation is running.", Computed: true},
		},
	}
}

func (r *googleDirectoryIntegrationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *googleDirectoryIntegrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan googleDirectoryIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("service_account_key_wo"), &plan.ServiceAccountKeyWO)...)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.createRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateGoogleDirectoryIntegration(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Google Workspace directory integration", err.Error())
		return
	}
	created, err := r.client.GetGoogleDirectoryIntegration(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Google Workspace directory integration", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	plan.ServiceAccountKeyWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *googleDirectoryIntegrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state googleDirectoryIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetGoogleDirectoryIntegration(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Google Workspace directory integration", err.Error())
		return
	}
	state.fromAPI(ctx, out, &resp.Diagnostics)
	state.ServiceAccountKeyWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *googleDirectoryIntegrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan googleDirectoryIntegrationModel
	var state googleDirectoryIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("service_account_key_wo"), &plan.ServiceAccountKeyWO)...)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.updateRequest(ctx, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateGoogleDirectoryIntegration(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update Google Workspace directory integration", err.Error())
		return
	}
	updated, err := r.client.GetGoogleDirectoryIntegration(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Google Workspace directory integration", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	plan.ServiceAccountKeyWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *googleDirectoryIntegrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state googleDirectoryIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteGoogleDirectoryIntegration(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Google Workspace directory integration", err.Error())
	}
}

func (r *googleDirectoryIntegrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m googleDirectoryIntegrationModel) createRequest(ctx context.Context, diags *diag.Diagnostics) client.GoogleDirectoryIntegrationCreateRequest {
	key := requiredWriteOnlyValue("service_account_key_wo", m.ServiceAccountKeyWO, diags)
	domains, domainDiags := directoryStringListPointer(ctx, m.Domains)
	diags.Append(domainDiags...)
	return client.GoogleDirectoryIntegrationCreateRequest{
		Enabled:                     directoryBoolPointer(m.Enabled),
		Description:                 m.Description.ValueString(),
		Info:                        directoryStringPointer(m.Info),
		Domains:                     domains,
		MaxUnlink:                   directoryStringPointer(m.MaxUnlink),
		DeleteUsers:                 directoryBoolPointer(m.DeleteUsers),
		AcknowledgeDisabledAccounts: directoryBoolPointer(m.AcknowledgeDisabledAccounts),
		User:                        m.User.ValueString(),
		Key:                         key,
	}
}

func (m googleDirectoryIntegrationModel) updateRequest(ctx context.Context, prior googleDirectoryIntegrationModel, diags *diag.Diagnostics) client.GoogleDirectoryIntegrationUpdateRequest {
	request := client.GoogleDirectoryIntegrationUpdateRequest{}
	request.AcknowledgeDisabledAccounts = changedDirectoryBool(m.AcknowledgeDisabledAccounts, prior.AcknowledgeDisabledAccounts)
	request.Enabled = changedDirectoryBool(m.Enabled, prior.Enabled)
	request.Description = changedDirectoryString(m.Description, prior.Description)
	request.Info = changedDirectoryString(m.Info, prior.Info)
	request.Domains = changedDirectoryStringList(ctx, m.Domains, prior.Domains, diags)
	request.MaxUnlink = changedDirectoryString(m.MaxUnlink, prior.MaxUnlink)
	request.DeleteUsers = changedDirectoryBool(m.DeleteUsers, prior.DeleteUsers)
	request.User = changedDirectoryString(m.User, prior.User)
	if directoryVersionChanged(m.ServiceAccountKeyWOVersion, prior.ServiceAccountKeyWOVersion) {
		key := requiredWriteOnlyValue("service_account_key_wo", m.ServiceAccountKeyWO, diags)
		if !diags.HasError() {
			request.Key = &key
		}
	}
	return request
}

func (m *googleDirectoryIntegrationModel) fromAPI(ctx context.Context, in client.GoogleDirectoryIntegration, diags *diag.Diagnostics) {
	setDirectoryBool(&m.Enabled, in.Enabled)
	setDirectoryString(&m.Description, in.Description)
	setDirectoryString(&m.Info, in.Info)
	setDirectoryStringList(ctx, &m.Domains, in.Domains, diags)
	setDirectoryUnlinkLimit(&m.MaxUnlink, in.MaxUnlink)
	setDirectoryBool(&m.DeleteUsers, in.DeleteUsers)
	setDirectoryBool(&m.AcknowledgeDisabledAccounts, in.AcknowledgeDisabledAccounts)
	setDirectoryString(&m.User, in.User)
	setDirectoryString(&m.LastSyncDateTime, in.LastSyncDateTime)
	setDirectoryString(&m.Status, in.Status)
	setDirectoryBool(&m.SyncRunning, in.SyncRunning)
}

type microsoft365DirectoryIntegrationModel struct {
	ID                          types.String `tfsdk:"id"`
	Description                 types.String `tfsdk:"description"`
	Info                        types.String `tfsdk:"info"`
	Domains                     types.List   `tfsdk:"domains"`
	ConnectorID                 types.String `tfsdk:"connector_id"`
	ClientID                    types.String `tfsdk:"client_id"`
	TenantDomain                types.String `tfsdk:"tenant_domain"`
	ServerSubtype               types.String `tfsdk:"server_subtype"`
	SyncGuestUsers              types.Bool   `tfsdk:"sync_guest_users"`
	AcknowledgeDisabledAccounts types.Bool   `tfsdk:"acknowledge_disabled_accounts"`
	Enabled                     types.Bool   `tfsdk:"enabled"`
	MaxUnlink                   types.String `tfsdk:"max_unlink"`
	SyncContacts                types.Bool   `tfsdk:"sync_contacts"`
	DeleteUsers                 types.Bool   `tfsdk:"delete_users"`
	LastSyncDateTime            types.String `tfsdk:"last_sync_date_time"`
	SyncRunning                 types.Bool   `tfsdk:"sync_running"`
}

type microsoft365DirectoryIntegrationResource struct{ client *client.Client }

func NewMicrosoft365DirectoryIntegrationResource() resource.Resource {
	return &microsoft365DirectoryIntegrationResource{}
}

func (r *microsoft365DirectoryIntegrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_microsoft_365_directory_integration"
}

func (r *microsoft365DirectoryIntegrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage a Mimecast Microsoft 365 directory integration.",
		Attributes: map[string]schema.Attribute{
			"id":                            idAttr("Mimecast Microsoft 365 directory integration ID."),
			"description":                   directoryRequiredString("Integration description.", 120),
			"info":                          directoryOptionalComputedString("Additional integration information.", 240),
			"domains":                       optionalComputedStringList("Domains synchronised by the integration."),
			"connector_id":                  optionalComputedString("Mimecast Cloud Connector ID."),
			"client_id":                     computedString("Microsoft 365 application client ID returned by Mimecast."),
			"tenant_domain":                 requiredString("Microsoft 365 tenant domain."),
			"server_subtype":                directoryOptionalComputedEnum("Microsoft 365 server subtype.", "standard", "gov"),
			"sync_guest_users":              optionalComputedBool("Whether Microsoft 365 guest users are synchronised."),
			"acknowledge_disabled_accounts": optionalComputedBool("Whether disabled directory accounts are acknowledged."),
			"enabled":                       optionalComputedBool("Whether the integration is enabled."),
			"max_unlink":                    directoryMaxUnlinkAttribute(),
			"sync_contacts":                 optionalComputedBool("Whether contacts are synchronised."),
			"delete_users":                  optionalComputedBool("Whether users removed from the directory are deleted from Mimecast."),
			"last_sync_date_time":           computedString("Time of the last directory synchronisation."),
			"sync_running":                  schema.BoolAttribute{Description: "Whether a directory synchronisation is running.", Computed: true},
		},
	}
}

func (r *microsoft365DirectoryIntegrationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *microsoft365DirectoryIntegrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan microsoft365DirectoryIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.createRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateMicrosoft365DirectoryIntegration(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Microsoft 365 directory integration", err.Error())
		return
	}
	created, err := r.client.GetMicrosoft365DirectoryIntegration(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created Microsoft 365 directory integration", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *microsoft365DirectoryIntegrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state microsoft365DirectoryIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetMicrosoft365DirectoryIntegration(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Microsoft 365 directory integration", err.Error())
		return
	}
	state.fromAPI(ctx, out, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *microsoft365DirectoryIntegrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan microsoft365DirectoryIntegrationModel
	var state microsoft365DirectoryIntegrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	request := plan.updateRequest(ctx, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateMicrosoft365DirectoryIntegration(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update Microsoft 365 directory integration", err.Error())
		return
	}
	updated, err := r.client.GetMicrosoft365DirectoryIntegration(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated Microsoft 365 directory integration", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *microsoft365DirectoryIntegrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state microsoft365DirectoryIntegrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteMicrosoft365DirectoryIntegration(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete Microsoft 365 directory integration", err.Error())
	}
}

func (r *microsoft365DirectoryIntegrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m microsoft365DirectoryIntegrationModel) createRequest(ctx context.Context, diags *diag.Diagnostics) client.Microsoft365DirectoryIntegrationCreateRequest {
	domains, domainDiags := directoryStringListPointer(ctx, m.Domains)
	diags.Append(domainDiags...)
	return client.Microsoft365DirectoryIntegrationCreateRequest{
		Description:                 m.Description.ValueString(),
		Info:                        directoryStringPointer(m.Info),
		Domains:                     domains,
		ConnectorID:                 directoryStringPointer(m.ConnectorID),
		TenantDomain:                m.TenantDomain.ValueString(),
		ServerSubtype:               directoryStringPointer(m.ServerSubtype),
		SyncGuestUsers:              directoryBoolPointer(m.SyncGuestUsers),
		AcknowledgeDisabledAccounts: directoryBoolPointer(m.AcknowledgeDisabledAccounts),
		Enabled:                     directoryBoolPointer(m.Enabled),
		MaxUnlink:                   directoryStringPointer(m.MaxUnlink),
		SyncContacts:                directoryBoolPointer(m.SyncContacts),
		DeleteUsers:                 directoryBoolPointer(m.DeleteUsers),
	}
}

func (m microsoft365DirectoryIntegrationModel) updateRequest(ctx context.Context, prior microsoft365DirectoryIntegrationModel, diags *diag.Diagnostics) client.Microsoft365DirectoryIntegrationUpdateRequest {
	return client.Microsoft365DirectoryIntegrationUpdateRequest{
		Description:                 changedDirectoryString(m.Description, prior.Description),
		Info:                        changedDirectoryString(m.Info, prior.Info),
		Domains:                     changedDirectoryStringList(ctx, m.Domains, prior.Domains, diags),
		ConnectorID:                 changedDirectoryString(m.ConnectorID, prior.ConnectorID),
		TenantDomain:                changedDirectoryString(m.TenantDomain, prior.TenantDomain),
		ServerSubtype:               changedDirectoryString(m.ServerSubtype, prior.ServerSubtype),
		SyncGuestUsers:              changedDirectoryBool(m.SyncGuestUsers, prior.SyncGuestUsers),
		AcknowledgeDisabledAccounts: changedDirectoryBool(m.AcknowledgeDisabledAccounts, prior.AcknowledgeDisabledAccounts),
		Enabled:                     changedDirectoryBool(m.Enabled, prior.Enabled),
		MaxUnlink:                   changedDirectoryString(m.MaxUnlink, prior.MaxUnlink),
		SyncContacts:                changedDirectoryBool(m.SyncContacts, prior.SyncContacts),
		DeleteUsers:                 changedDirectoryBool(m.DeleteUsers, prior.DeleteUsers),
	}
}

func (m *microsoft365DirectoryIntegrationModel) fromAPI(ctx context.Context, in client.Microsoft365DirectoryIntegration, diags *diag.Diagnostics) {
	setDirectoryString(&m.Description, in.Description)
	setDirectoryString(&m.Info, in.Info)
	setDirectoryStringList(ctx, &m.Domains, in.Domains, diags)
	setDirectoryString(&m.ConnectorID, in.ConnectorID)
	setDirectoryString(&m.ClientID, in.ClientID)
	setDirectoryString(&m.TenantDomain, in.TenantDomain)
	setDirectoryString(&m.ServerSubtype, in.ServerSubtype)
	setDirectoryBool(&m.SyncGuestUsers, in.SyncGuestUsers)
	setDirectoryBool(&m.AcknowledgeDisabledAccounts, in.AcknowledgeDisabledAccounts)
	setDirectoryBool(&m.Enabled, in.Enabled)
	setDirectoryUnlinkLimit(&m.MaxUnlink, in.MaxUnlink)
	setDirectoryBool(&m.SyncContacts, in.SyncContacts)
	setDirectoryBool(&m.DeleteUsers, in.DeleteUsers)
	setDirectoryString(&m.LastSyncDateTime, in.LastSyncDateTime)
	setDirectoryBool(&m.SyncRunning, in.SyncRunning)
}

func directoryRequiredString(description string, maxLength int) schema.StringAttribute {
	return schema.StringAttribute{
		Description: description,
		Required:    true,
		Validators:  []validator.String{stringvalidator.LengthAtMost(maxLength)},
	}
}

func directoryOptionalComputedString(description string, maxLength int) schema.StringAttribute {
	return schema.StringAttribute{
		Description:   description,
		Optional:      true,
		Computed:      true,
		Validators:    []validator.String{stringvalidator.LengthAtMost(maxLength)},
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func directoryOptionalComputedEnum(description string, values ...string) schema.StringAttribute {
	return schema.StringAttribute{
		Description:   description,
		Optional:      true,
		Computed:      true,
		Validators:    []validator.String{stringvalidator.OneOf(values...)},
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func directoryMaxUnlinkAttribute() schema.StringAttribute {
	return directoryOptionalComputedEnum("Maximum number of users that one synchronisation may unlink.", directoryMaxUnlinkValues...)
}

func directoryOptionalComputedPort() schema.Int64Attribute {
	return schema.Int64Attribute{
		Description:   "Port used to connect to Active Directory.",
		Optional:      true,
		Computed:      true,
		Validators:    []validator.Int64{int64validator.Between(1, 65535)},
		PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
	}
}

func directoryWriteOnlyString(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Description: description,
		Optional:    true,
		WriteOnly:   true,
		Sensitive:   true,
		Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
	}
}

func directoryWriteOnlyVersion(description string) schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: description,
		Optional:    true,
		Validators:  []validator.Int64{int64validator.AtLeast(1)},
	}
}

func requiredWriteOnlyValue(name string, value types.String, diags *diag.Diagnostics) string {
	if value.IsNull() || value.IsUnknown() || value.ValueString() == "" {
		diags.AddError("Missing write-only value", name+" must be configured when its version trigger changes.")
		return ""
	}
	return value.ValueString()
}

func directoryVersionChanged(planned, prior types.Int64) bool {
	return !planned.IsNull() && !planned.IsUnknown() && !planned.Equal(prior)
}

func directoryStringPointer(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	v := value.ValueString()
	return &v
}

func directoryInt64Pointer(value types.Int64) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	v := value.ValueInt64()
	return &v
}

func directoryBoolPointer(value types.Bool) *bool {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	v := value.ValueBool()
	return &v
}

func directoryStringListPointer(ctx context.Context, value types.List) (*[]string, diag.Diagnostics) {
	if value.IsNull() || value.IsUnknown() {
		return nil, nil
	}
	values, diags := stringsFromList(ctx, value)
	return &values, diags
}

func changedDirectoryString(planned, prior types.String) *string {
	if planned.IsUnknown() || planned.Equal(prior) {
		return nil
	}
	v := planned.ValueString()
	return &v
}

func changedDirectoryInt64(planned, prior types.Int64) *int64 {
	if planned.IsUnknown() || planned.Equal(prior) {
		return nil
	}
	v := planned.ValueInt64()
	return &v
}

func changedDirectoryBool(planned, prior types.Bool) *bool {
	if planned.IsUnknown() || planned.Equal(prior) {
		return nil
	}
	v := planned.ValueBool()
	return &v
}

func changedDirectoryStringList(ctx context.Context, planned, prior types.List, diags *diag.Diagnostics) *[]string {
	// The framework's zero-value List is null but has no element type, so Equal
	// returns false even against another zero-value List. Treat null pairs and
	// planned unknown values as unchanged before using the typed equality check.
	if planned.IsUnknown() || (planned.IsNull() && prior.IsNull()) || planned.Equal(prior) {
		return nil
	}
	values, listDiags := stringsFromList(ctx, planned)
	diags.Append(listDiags...)
	return &values
}

func setDirectoryString(target *types.String, value *string) {
	if value != nil {
		*target = stringValue(*value)
	} else if target.IsUnknown() {
		*target = types.StringNull()
	}
}

func setDirectoryInt64(target *types.Int64, value *int64) {
	if value != nil {
		*target = types.Int64Value(*value)
	} else if target.IsUnknown() {
		*target = types.Int64Null()
	}
}

func setDirectoryBool(target *types.Bool, value *bool) {
	if value != nil {
		*target = types.BoolValue(*value)
	} else if target.IsUnknown() {
		*target = types.BoolNull()
	}
}

func setDirectoryStringList(ctx context.Context, target *types.List, value *[]string, diags *diag.Diagnostics) {
	if value != nil {
		list, listDiags := listFromStrings(ctx, *value)
		diags.Append(listDiags...)
		*target = list
	} else if target.IsUnknown() {
		*target = types.ListNull(types.StringType)
	}
}

func setDirectoryUnlinkLimit(target *types.String, value *client.UnlinkLimit) {
	if value != nil {
		*target = stringValue(string(*value))
	} else if target.IsUnknown() {
		*target = types.StringNull()
	}
}
