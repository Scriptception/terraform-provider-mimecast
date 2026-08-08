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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type journalingServiceResourceModel struct {
	ID                              types.String `tfsdk:"id"`
	Description                     types.String `tfsdk:"description"`
	Enabled                         types.Bool   `tfsdk:"enabled"`
	MessageFormat                   types.String `tfsdk:"message_format"`
	RemoveJournalHeaders            types.Bool   `tfsdk:"remove_journal_headers"`
	JournalNonInternalAddresses     types.Bool   `tfsdk:"journal_non_internal_addresses"`
	JournalUnknownInternalAddresses types.Bool   `tfsdk:"journal_unknown_internal_addresses"`
	TransferProtocol                types.String `tfsdk:"transfer_protocol"`

	SMTPEmailAddress          types.String `tfsdk:"smtp_email_address"`
	SMTPIPRanges              types.List   `tfsdk:"smtp_ip_ranges"`
	SMTPUsesAuthentication    types.Bool   `tfsdk:"smtp_uses_authentication"`
	SMTPPasswordWO            types.String `tfsdk:"smtp_password_wo"`
	SMTPPasswordWOVersion     types.Int64  `tfsdk:"smtp_password_wo_version"`
	SMTPUsesTLS               types.Bool   `tfsdk:"smtp_uses_tls"`
	SMTPPrefersClearText      types.Bool   `tfsdk:"smtp_prefers_clear_text"`
	SMTPExtendedDeduplication types.Bool   `tfsdk:"smtp_extended_deduplication"`
	SMTPDeliveryWaitAttempts  types.Int64  `tfsdk:"smtp_delivery_wait_attempts"`
	SMTPInactivityTimeout     types.Int64  `tfsdk:"smtp_inactivity_timeout"`
	SMTPProcessInitialDelay   types.Int64  `tfsdk:"smtp_process_initial_delay"`
	SMTPHostnames             types.List   `tfsdk:"smtp_hostnames"`

	POP3EmailAddress             types.String `tfsdk:"pop3_email_address"`
	POP3Mailbox                  types.String `tfsdk:"pop3_mailbox"`
	POP3PasswordWO               types.String `tfsdk:"pop3_password_wo"`
	POP3PasswordWOVersion        types.Int64  `tfsdk:"pop3_password_wo_version"`
	POP3Host                     types.String `tfsdk:"pop3_host"`
	POP3Port                     types.Int64  `tfsdk:"pop3_port"`
	POP3UsesPOP3S                types.Bool   `tfsdk:"pop3_uses_pop3s"`
	POP3EncryptionIsRelaxed      types.Bool   `tfsdk:"pop3_encryption_is_relaxed"`
	POP3DetailedLoggingIsEnabled types.Bool   `tfsdk:"pop3_detailed_logging_is_enabled"`

	QueueSize            types.Int64  `tfsdk:"queue_size"`
	Status               types.String `tfsdk:"status"`
	LastReceivedDateTime types.String `tfsdk:"last_received_date_time"`
}

type journalingServiceResource struct{ client *client.Client }

func NewJournalingServiceResource() resource.Resource { return &journalingServiceResource{} }

func (r *journalingServiceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_journaling_service"
}

func (r *journalingServiceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage a Mimecast Cloud Gateway journaling service.",
		Attributes: map[string]schema.Attribute{
			"id":                                 idAttr("Mimecast journaling service ID."),
			"description":                        requiredString("Description identifying the journaling service."),
			"enabled":                            optionalComputedBool("Whether the journaling service is enabled."),
			"message_format":                     journalingOptionalComputedEnum("Journal message format.", "standard_eml", "exchange_env"),
			"remove_journal_headers":             optionalComputedBool("Whether Mimecast removes Microsoft Exchange journal headers."),
			"journal_non_internal_addresses":     optionalComputedBool("Whether messages without an internal address are archived."),
			"journal_unknown_internal_addresses": optionalComputedBool("Whether messages with unknown internal addresses are archived."),
			"transfer_protocol":                  schema.StringAttribute{Description: "Journaling transfer protocol.", Required: true, Validators: []validator.String{stringvalidator.OneOf("smtp", "pop3")}},
			"smtp_email_address":                 optionalComputedString("SMTP journaling email address."),
			"smtp_ip_ranges":                     optionalComputedStringList("Additional IPv4 CIDR ranges permitted to submit SMTP journal messages."),
			"smtp_uses_authentication":           optionalComputedBool("Whether SMTP password authentication is required."),
			"smtp_password_wo":                   directoryWriteOnlyString("SMTP journaling password. Write-only; increment smtp_password_wo_version when changing it."),
			"smtp_password_wo_version":           directoryWriteOnlyVersion("Version trigger for smtp_password_wo. Increment this when changing the password."),
			"smtp_uses_tls":                      optionalComputedBool("Whether SMTP journal traffic uses TLS."),
			"smtp_prefers_clear_text":            optionalComputedBool("Whether Active Directory protected journal items prefer clear text."),
			"smtp_extended_deduplication":        optionalComputedBool("Whether extended deduplication is enabled."),
			"smtp_delivery_wait_attempts":        journalingOptionalComputedInt64("Number of attempts to match a message before archiving.", int64validator.AtLeast(0)),
			"smtp_inactivity_timeout":            journalingOptionalComputedInt64("Minutes without journal activity before the service enters an error state.", int64validator.Between(180, 960)),
			"smtp_process_initial_delay":         journalingOptionalComputedInt64("Minutes to wait before matching a message to the archive.", int64validator.AtLeast(0)),
			"smtp_hostnames":                     schema.ListAttribute{Description: "Journal Send Connector hostnames returned by Mimecast.", Computed: true, ElementType: types.StringType},
			"pop3_email_address":                 optionalComputedString("POP3 journal mailbox email address."),
			"pop3_mailbox":                       optionalComputedString("POP3 journal mailbox username."),
			"pop3_password_wo":                   directoryWriteOnlyString("POP3 journal mailbox password. Write-only; increment pop3_password_wo_version when changing it."),
			"pop3_password_wo_version":           directoryWriteOnlyVersion("Version trigger for pop3_password_wo. Increment this when changing the password."),
			"pop3_host":                          optionalComputedString("POP3 journal mailbox hostname or IP address."),
			"pop3_port":                          journalingOptionalComputedInt64("POP3 journal mailbox TCP port.", int64validator.Between(1, 65535)),
			"pop3_uses_pop3s":                    optionalComputedBool("Whether the journal mailbox is accessed using POP3S."),
			"pop3_encryption_is_relaxed":         optionalComputedBool("Whether relaxed POP3 certificate validation is enabled."),
			"pop3_detailed_logging_is_enabled":   optionalComputedBool("Whether detailed POP3 troubleshooting logs are enabled."),
			"queue_size":                         schema.Int64Attribute{Description: "Number of messages in the journaling queue.", Computed: true},
			"status":                             computedString("Journaling service status."),
			"last_received_date_time":            computedString("Time the last journal message was received."),
		},
	}
}

func (r *journalingServiceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}

func (r *journalingServiceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan journalingServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("smtp_password_wo"), &plan.SMTPPasswordWO)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("pop3_password_wo"), &plan.POP3PasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.createRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateJournalingServiceResource(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create journaling service", err.Error())
		return
	}
	created, err := r.client.GetJournalingServiceResource(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created journaling service", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	plan.clearWriteOnlyValues()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *journalingServiceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state journalingServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetJournalingServiceResource(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read journaling service", err.Error())
		return
	}
	state.fromAPI(ctx, out, &resp.Diagnostics)
	state.clearWriteOnlyValues()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *journalingServiceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan journalingServiceResourceModel
	var state journalingServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("smtp_password_wo"), &plan.SMTPPasswordWO)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("pop3_password_wo"), &plan.POP3PasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.updateRequest(ctx, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateJournalingServiceResource(ctx, plan.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Unable to update journaling service", err.Error())
		return
	}
	updated, err := r.client.GetJournalingServiceResource(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated journaling service", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	plan.clearWriteOnlyValues()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *journalingServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state journalingServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteJournalingServiceResource(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete journaling service", err.Error())
	}
}

func (r *journalingServiceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m journalingServiceResourceModel) createRequest(ctx context.Context, diags *diag.Diagnostics) client.JournalingServiceCreateRequest {
	request := client.JournalingServiceCreateRequest{
		Description:                     m.Description.ValueString(),
		Enabled:                         directoryBoolPointer(m.Enabled),
		MessageFormat:                   directoryStringPointer(m.MessageFormat),
		RemoveJournalHeaders:            directoryBoolPointer(m.RemoveJournalHeaders),
		JournalNonInternalAddresses:     directoryBoolPointer(m.JournalNonInternalAddresses),
		JournalUnknownInternalAddresses: directoryBoolPointer(m.JournalUnknownInternalAddresses),
	}

	switch m.TransferProtocol.ValueString() {
	case "smtp":
		request.SMTPJournalingConnection = m.smtpCreateRequest(ctx, diags)
	case "pop3":
		request.POP3JournalingConnection = m.pop3CreateRequest(diags)
	default:
		diags.AddError("Invalid journaling transfer protocol", "transfer_protocol must be smtp or pop3.")
	}
	return request
}

func (m journalingServiceResourceModel) smtpCreateRequest(ctx context.Context, diags *diag.Diagnostics) *client.SMTPJournalingConnectionCreate {
	emailAddress := journalingRequiredString("smtp_email_address", m.SMTPEmailAddress, diags)
	ipRanges, rangeDiags := directoryStringListPointer(ctx, m.SMTPIPRanges)
	diags.Append(rangeDiags...)
	request := &client.SMTPJournalingConnectionCreate{
		EmailAddress:          emailAddress,
		IPRanges:              ipRanges,
		UsesAuthentication:    directoryBoolPointer(m.SMTPUsesAuthentication),
		UsesTLS:               directoryBoolPointer(m.SMTPUsesTLS),
		PrefersClearText:      directoryBoolPointer(m.SMTPPrefersClearText),
		ExtendedDeduplication: directoryBoolPointer(m.SMTPExtendedDeduplication),
		DeliveryWaitAttempts:  directoryInt64Pointer(m.SMTPDeliveryWaitAttempts),
		InactivityTimeout:     directoryInt64Pointer(m.SMTPInactivityTimeout),
		ProcessInitialDelay:   directoryInt64Pointer(m.SMTPProcessInitialDelay),
	}
	if !m.SMTPPasswordWO.IsNull() && !m.SMTPPasswordWO.IsUnknown() {
		password := m.SMTPPasswordWO.ValueString()
		request.Password = &password
	}
	if m.SMTPUsesAuthentication.ValueBool() && request.Password == nil {
		password := requiredWriteOnlyValue("smtp_password_wo", m.SMTPPasswordWO, diags)
		if !diags.HasError() {
			request.Password = &password
		}
	}
	return request
}

func (m journalingServiceResourceModel) pop3CreateRequest(diags *diag.Diagnostics) *client.POP3JournalingConnectionCreate {
	return &client.POP3JournalingConnectionCreate{
		EmailAddress:             journalingRequiredString("pop3_email_address", m.POP3EmailAddress, diags),
		Mailbox:                  journalingRequiredString("pop3_mailbox", m.POP3Mailbox, diags),
		Password:                 requiredWriteOnlyValue("pop3_password_wo", m.POP3PasswordWO, diags),
		Host:                     journalingRequiredString("pop3_host", m.POP3Host, diags),
		Port:                     directoryInt64Pointer(m.POP3Port),
		UsesPOP3S:                directoryBoolPointer(m.POP3UsesPOP3S),
		EncryptionIsRelaxed:      directoryBoolPointer(m.POP3EncryptionIsRelaxed),
		DetailedLoggingIsEnabled: directoryBoolPointer(m.POP3DetailedLoggingIsEnabled),
	}
}

func (m journalingServiceResourceModel) updateRequest(ctx context.Context, prior journalingServiceResourceModel, diags *diag.Diagnostics) client.JournalingServiceUpdateRequest {
	request := client.JournalingServiceUpdateRequest{
		Description:                     changedDirectoryString(m.Description, prior.Description),
		Enabled:                         changedDirectoryBool(m.Enabled, prior.Enabled),
		MessageFormat:                   changedDirectoryString(m.MessageFormat, prior.MessageFormat),
		RemoveJournalHeaders:            changedDirectoryBool(m.RemoveJournalHeaders, prior.RemoveJournalHeaders),
		JournalNonInternalAddresses:     changedDirectoryBool(m.JournalNonInternalAddresses, prior.JournalNonInternalAddresses),
		JournalUnknownInternalAddresses: changedDirectoryBool(m.JournalUnknownInternalAddresses, prior.JournalUnknownInternalAddresses),
		TransferProtocol:                changedDirectoryString(m.TransferProtocol, prior.TransferProtocol),
	}

	protocolChanged := request.TransferProtocol != nil
	request.SMTPJournalingConnection = m.smtpUpdateRequest(ctx, prior, protocolChanged && m.TransferProtocol.ValueString() == "smtp", diags)
	request.POP3JournalingConnection = m.pop3UpdateRequest(prior, protocolChanged && m.TransferProtocol.ValueString() == "pop3", diags)
	return request
}

func (m journalingServiceResourceModel) smtpUpdateRequest(ctx context.Context, prior journalingServiceResourceModel, switching bool, diags *diag.Diagnostics) *client.SMTPJournalingConnectionUpdate {
	request := &client.SMTPJournalingConnectionUpdate{}
	if switching {
		request.EmailAddress = journalingRequiredStringPointer("smtp_email_address", m.SMTPEmailAddress, diags)
		request.IPRanges = journalingStringListPointer(ctx, m.SMTPIPRanges, diags)
		request.UseAuthentication = directoryBoolPointer(m.SMTPUsesAuthentication)
		request.UseTLS = directoryBoolPointer(m.SMTPUsesTLS)
		request.PreferClearText = directoryBoolPointer(m.SMTPPrefersClearText)
		request.ExtendedDeduplication = directoryBoolPointer(m.SMTPExtendedDeduplication)
		request.DeliveryWaitAttempts = directoryInt64Pointer(m.SMTPDeliveryWaitAttempts)
		request.InactivityTimeout = directoryInt64Pointer(m.SMTPInactivityTimeout)
		request.ProcessInitialDelay = directoryInt64Pointer(m.SMTPProcessInitialDelay)
	} else {
		request.EmailAddress = changedDirectoryString(m.SMTPEmailAddress, prior.SMTPEmailAddress)
		request.IPRanges = changedDirectoryStringList(ctx, m.SMTPIPRanges, prior.SMTPIPRanges, diags)
		request.UseAuthentication = changedDirectoryBool(m.SMTPUsesAuthentication, prior.SMTPUsesAuthentication)
		request.UseTLS = changedDirectoryBool(m.SMTPUsesTLS, prior.SMTPUsesTLS)
		request.PreferClearText = changedDirectoryBool(m.SMTPPrefersClearText, prior.SMTPPrefersClearText)
		request.ExtendedDeduplication = changedDirectoryBool(m.SMTPExtendedDeduplication, prior.SMTPExtendedDeduplication)
		request.DeliveryWaitAttempts = changedDirectoryInt64(m.SMTPDeliveryWaitAttempts, prior.SMTPDeliveryWaitAttempts)
		request.InactivityTimeout = changedDirectoryInt64(m.SMTPInactivityTimeout, prior.SMTPInactivityTimeout)
		request.ProcessInitialDelay = changedDirectoryInt64(m.SMTPProcessInitialDelay, prior.SMTPProcessInitialDelay)
	}

	authenticationEnabled := request.UseAuthentication != nil && *request.UseAuthentication
	sendPassword := directoryVersionChanged(m.SMTPPasswordWOVersion, prior.SMTPPasswordWOVersion) || authenticationEnabled
	if sendPassword {
		password := requiredWriteOnlyValue("smtp_password_wo", m.SMTPPasswordWO, diags)
		if !diags.HasError() {
			request.Password = &password
		}
	}
	if journalingSMTPUpdateEmpty(request) {
		return nil
	}
	return request
}

func (m journalingServiceResourceModel) pop3UpdateRequest(prior journalingServiceResourceModel, switching bool, diags *diag.Diagnostics) *client.POP3JournalingConnectionUpdate {
	request := &client.POP3JournalingConnectionUpdate{}
	if switching {
		request.EmailAddress = journalingRequiredStringPointer("pop3_email_address", m.POP3EmailAddress, diags)
		request.Mailbox = journalingRequiredStringPointer("pop3_mailbox", m.POP3Mailbox, diags)
		request.Host = journalingRequiredStringPointer("pop3_host", m.POP3Host, diags)
		request.Port = directoryInt64Pointer(m.POP3Port)
		request.UsePOP3 = directoryBoolPointer(m.POP3UsesPOP3S)
		request.RelaxedEncryption = directoryBoolPointer(m.POP3EncryptionIsRelaxed)
		request.DetailedLogging = directoryBoolPointer(m.POP3DetailedLoggingIsEnabled)
	} else {
		request.EmailAddress = changedDirectoryString(m.POP3EmailAddress, prior.POP3EmailAddress)
		request.Mailbox = changedDirectoryString(m.POP3Mailbox, prior.POP3Mailbox)
		request.Host = changedDirectoryString(m.POP3Host, prior.POP3Host)
		request.Port = changedDirectoryInt64(m.POP3Port, prior.POP3Port)
		request.UsePOP3 = changedDirectoryBool(m.POP3UsesPOP3S, prior.POP3UsesPOP3S)
		request.RelaxedEncryption = changedDirectoryBool(m.POP3EncryptionIsRelaxed, prior.POP3EncryptionIsRelaxed)
		request.DetailedLogging = changedDirectoryBool(m.POP3DetailedLoggingIsEnabled, prior.POP3DetailedLoggingIsEnabled)
	}

	if switching || directoryVersionChanged(m.POP3PasswordWOVersion, prior.POP3PasswordWOVersion) {
		password := requiredWriteOnlyValue("pop3_password_wo", m.POP3PasswordWO, diags)
		if !diags.HasError() {
			request.Password = &password
		}
	}
	if journalingPOP3UpdateEmpty(request) {
		return nil
	}
	return request
}

func (m *journalingServiceResourceModel) fromAPI(ctx context.Context, in client.JournalingServiceRead, diags *diag.Diagnostics) {
	setDirectoryString(&m.ID, in.ID)
	setDirectoryString(&m.Description, in.Description)
	setDirectoryBool(&m.Enabled, in.Enabled)
	setDirectoryString(&m.MessageFormat, in.MessageFormat)
	setDirectoryBool(&m.RemoveJournalHeaders, in.RemoveJournalHeaders)
	setDirectoryBool(&m.JournalNonInternalAddresses, in.JournalNonInternalAddresses)
	setDirectoryBool(&m.JournalUnknownInternalAddresses, in.JournalUnknownInternalAddresses)
	setDirectoryString(&m.TransferProtocol, in.TransferProtocol)
	setDirectoryInt64(&m.QueueSize, in.QueueSize)

	if in.SMTPJournalingConnection != nil {
		connection := in.SMTPJournalingConnection
		setDirectoryString(&m.SMTPEmailAddress, connection.EmailAddress)
		setDirectoryStringList(ctx, &m.SMTPIPRanges, connection.IPRanges, diags)
		setDirectoryBool(&m.SMTPUsesAuthentication, connection.UsesAuthentication)
		setDirectoryBool(&m.SMTPUsesTLS, connection.UsesTLS)
		setDirectoryBool(&m.SMTPPrefersClearText, connection.PrefersClearText)
		setDirectoryBool(&m.SMTPExtendedDeduplication, connection.ExtendedDeduplication)
		setDirectoryInt64(&m.SMTPDeliveryWaitAttempts, connection.DeliveryWaitAttempts)
		setDirectoryInt64(&m.SMTPInactivityTimeout, connection.InactivityTimeout)
		setDirectoryInt64(&m.SMTPProcessInitialDelay, connection.ProcessInitialDelay)
		setDirectoryStringList(ctx, &m.SMTPHostnames, connection.Hostnames, diags)
	}
	if in.POP3JournalingConnection != nil {
		connection := in.POP3JournalingConnection
		setDirectoryString(&m.POP3EmailAddress, connection.EmailAddress)
		setDirectoryString(&m.POP3Mailbox, connection.Mailbox)
		setDirectoryString(&m.POP3Host, connection.Host)
		setDirectoryInt64(&m.POP3Port, connection.Port)
		setDirectoryBool(&m.POP3UsesPOP3S, connection.UsesPOP3S)
		setDirectoryBool(&m.POP3EncryptionIsRelaxed, connection.EncryptionIsRelaxed)
		setDirectoryBool(&m.POP3DetailedLoggingIsEnabled, connection.DetailedLoggingIsEnabled)
	}
	if in.StatusInfo != nil {
		setDirectoryString(&m.Status, in.StatusInfo.Status)
		setDirectoryString(&m.LastReceivedDateTime, in.StatusInfo.LastReceivedDateTime)
	}
}

func (m *journalingServiceResourceModel) clearWriteOnlyValues() {
	m.SMTPPasswordWO = types.StringNull()
	m.POP3PasswordWO = types.StringNull()
}

func journalingOptionalComputedEnum(description string, values ...string) schema.StringAttribute {
	return directoryOptionalComputedEnum(description, values...)
}

func journalingOptionalComputedInt64(description string, validators ...validator.Int64) schema.Int64Attribute {
	return schema.Int64Attribute{
		Description:   description,
		Optional:      true,
		Computed:      true,
		Validators:    validators,
		PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
	}
}

func journalingRequiredString(name string, value types.String, diags *diag.Diagnostics) string {
	if value.IsNull() || value.IsUnknown() || value.ValueString() == "" {
		diags.AddError("Missing journaling connection value", name+" must be configured for the selected transfer protocol.")
		return ""
	}
	return value.ValueString()
}

func journalingRequiredStringPointer(name string, value types.String, diags *diag.Diagnostics) *string {
	result := journalingRequiredString(name, value, diags)
	if result == "" {
		return nil
	}
	return &result
}

func journalingStringListPointer(ctx context.Context, value types.List, diags *diag.Diagnostics) *[]string {
	result, listDiags := directoryStringListPointer(ctx, value)
	diags.Append(listDiags...)
	return result
}

func journalingSMTPUpdateEmpty(request *client.SMTPJournalingConnectionUpdate) bool {
	return request.EmailAddress == nil && request.IPRanges == nil && request.UseAuthentication == nil && request.Password == nil && request.UseTLS == nil &&
		request.PreferClearText == nil && request.ExtendedDeduplication == nil && request.DeliveryWaitAttempts == nil && request.InactivityTimeout == nil && request.ProcessInitialDelay == nil
}

func journalingPOP3UpdateEmpty(request *client.POP3JournalingConnectionUpdate) bool {
	return request.EmailAddress == nil && request.Mailbox == nil && request.Password == nil && request.Host == nil && request.Port == nil && request.UsePOP3 == nil &&
		request.RelaxedEncryption == nil && request.DetailedLogging == nil
}
