package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type deliveryRouteDefinitionModel struct {
	ID               types.String `tfsdk:"id"`
	Description      types.String `tfsdk:"description"`
	Hostname         types.String `tfsdk:"hostname"`
	Port             types.Int64  `tfsdk:"port"`
	AlternateRouteID types.String `tfsdk:"alternate_route_id"`
	AuthMechanisms   types.List   `tfsdk:"auth_mechanisms"`
	Username         types.String `tfsdk:"username"`
	PasswordWO       types.String `tfsdk:"password_wo"`
	PasswordVersion  types.Int64  `tfsdk:"password_wo_version"`
	Domain           types.String `tfsdk:"domain"`
}

type deliveryRouteDefinitionResource struct{ client *client.Client }

func NewDeliveryRouteDefinitionResource() resource.Resource {
	return &deliveryRouteDefinitionResource{}
}
func (r *deliveryRouteDefinitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_delivery_route_definition"
}
func (r *deliveryRouteDefinitionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast Cloud Gateway delivery route definition.", Attributes: map[string]schema.Attribute{
		"id":                  idAttr("Mimecast delivery route definition ID."),
		"description":         requiredString("Definition description."),
		"hostname":            requiredString("Public hostname or IP address of the email server."),
		"port":                schema.Int64Attribute{Description: "Port to connect on.", Required: true, Validators: []validator.Int64{int64validator.Between(1, 65535)}},
		"alternate_route_id":  optionalString("Alternate delivery route definition ID."),
		"auth_mechanisms":     optionalStringList("SMTP authentication mechanisms in preferred order."),
		"username":            optionalString("SMTP authentication username."),
		"password_wo":         schema.StringAttribute{Description: "SMTP authentication password. Write-only; pair with password_wo_version to send updates.", Optional: true, WriteOnly: true, Sensitive: true},
		"password_wo_version": schema.Int64Attribute{Description: "Version trigger for password_wo. Increment this when changing the write-only password.", Optional: true, Validators: []validator.Int64{nonNegativeInt64Validator{}}},
		"domain":              optionalString("SMTP authentication domain."),
	}}
}
func (r *deliveryRouteDefinitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}
func (r *deliveryRouteDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan deliveryRouteDefinitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("password_wo"), &plan.PasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}
	includePassword := !plan.PasswordWO.IsNull() && !plan.PasswordWO.IsUnknown() && plan.PasswordWO.ValueString() != ""
	id, err := r.client.CreateDeliveryRouteDefinition(ctx, plan.toAPI(ctx, &resp.Diagnostics, includePassword))
	if err != nil {
		resp.Diagnostics.AddError("Unable to create delivery route definition", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetDeliveryRouteDefinition(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created delivery route definition", err.Error())
		return
	}
	plan.fromAPI(ctx, created, &resp.Diagnostics)
	plan.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *deliveryRouteDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state deliveryRouteDefinitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetDeliveryRouteDefinition(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read delivery route definition", err.Error())
		return
	}
	state.fromAPI(ctx, out, &resp.Diagnostics)
	state.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *deliveryRouteDefinitionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan deliveryRouteDefinitionModel
	var state deliveryRouteDefinitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("password_wo"), &plan.PasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}
	update := plan.updateAPI(ctx, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateDeliveryRouteDefinition(ctx, plan.ID.ValueString(), update); err != nil {
		resp.Diagnostics.AddError("Unable to update delivery route definition", err.Error())
		return
	}
	updated, err := r.client.GetDeliveryRouteDefinition(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated delivery route definition", err.Error())
		return
	}
	plan.fromAPI(ctx, updated, &resp.Diagnostics)
	plan.PasswordWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *deliveryRouteDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state deliveryRouteDefinitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteDeliveryRouteDefinition(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete delivery route definition", err.Error())
	}
}
func (r *deliveryRouteDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m deliveryRouteDefinitionModel) toAPI(ctx context.Context, diags *diag.Diagnostics, includePassword bool) client.DeliveryRouteDefinition {
	mechs, d := stringsFromList(ctx, m.AuthMechanisms)
	diags.Append(d...)
	out := client.DeliveryRouteDefinition{
		ID: m.ID.ValueString(), Description: m.Description.ValueString(), Hostname: m.Hostname.ValueString(), Port: m.Port.ValueInt64(),
		AlternateRouteID: m.AlternateRouteID.ValueString(), AuthMechanisms: mechs, Username: m.Username.ValueString(), Domain: m.Domain.ValueString(),
	}
	if len(mechs) > 0 || m.Username.ValueString() != "" || includePassword {
		out.SMTPAuth = &client.SMTPAuthentication{AuthMechanisms: mechs, Username: m.Username.ValueString(), Domain: m.Domain.ValueString()}
		if includePassword {
			out.SMTPAuth.Password = m.PasswordWO.ValueString()
		}
	}
	return out
}

func (m deliveryRouteDefinitionModel) updateAPI(ctx context.Context, prior deliveryRouteDefinitionModel, diags *diag.Diagnostics) client.DeliveryRouteDefinition {
	includePassword := writeOnlyVersionChanged(m.PasswordVersion, prior.PasswordVersion)
	if includePassword && (m.PasswordWO.IsNull() || m.PasswordWO.IsUnknown() || m.PasswordWO.ValueString() == "") {
		diags.AddError("Missing delivery route password", "password_wo must be configured when password_wo_version changes.")
		includePassword = false
	}
	return m.toAPI(ctx, diags, includePassword)
}

func writeOnlyVersionChanged(planned, prior types.Int64) bool {
	if planned.IsNull() || planned.IsUnknown() {
		return false
	}
	if prior.IsNull() || prior.IsUnknown() {
		return true
	}
	return planned.ValueInt64() != prior.ValueInt64()
}

func (m *deliveryRouteDefinitionModel) fromAPI(ctx context.Context, in client.DeliveryRouteDefinition, diags *diag.Diagnostics) {
	m.Description = stringValue(in.Description)
	m.Hostname = stringValue(in.Hostname)
	m.Port = int64Value(in.Port)
	m.AlternateRouteID = stringValue(in.AlternateRouteID)
	authMechanisms, username, domain := deliveryRouteAuthenticationFromAPI(in)
	m.Username = stringValue(username)
	m.Domain = stringValue(domain)
	var d diag.Diagnostics
	m.AuthMechanisms, d = listFromStrings(ctx, authMechanisms)
	diags.Append(d...)
}

func deliveryRouteAuthenticationFromAPI(in client.DeliveryRouteDefinition) ([]string, string, string) {
	authMechanisms := in.AuthMechanisms
	username := in.Username
	domain := in.Domain
	if in.SMTPAuth != nil {
		authMechanisms = in.SMTPAuth.AuthMechanisms
		username = in.SMTPAuth.Username
		domain = in.SMTPAuth.Domain
	}

	canonical := make([]string, 0, len(authMechanisms))
	for _, mechanism := range authMechanisms {
		if mechanism = strings.TrimSpace(mechanism); mechanism != "" {
			canonical = append(canonical, mechanism)
		}
	}
	if len(canonical) == 0 {
		canonical = nil
	}

	return canonical, username, domain
}

type dnsOutboundDefinitionModel struct {
	ID          types.String `tfsdk:"id"`
	Description types.String `tfsdk:"description"`
	Domain      types.String `tfsdk:"domain"`
	Selector    types.String `tfsdk:"selector"`
	SignDKIM    types.Bool   `tfsdk:"sign_dkim"`
	KeyLength   types.Int64  `tfsdk:"key_length"`
	DNSAddress  types.String `tfsdk:"dns_address"`
	PublicKey   types.String `tfsdk:"public_key"`
	Validated   types.Bool   `tfsdk:"validated"`
}

type dnsOutboundDefinitionResource struct{ client *client.Client }

func NewDNSAuthenticationOutboundDefinitionResource() resource.Resource {
	return &dnsOutboundDefinitionResource{}
}
func (r *dnsOutboundDefinitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns_authentication_outbound_definition"
}
func (r *dnsOutboundDefinitionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage a Mimecast DNS authentication outbound definition.", Attributes: map[string]schema.Attribute{
		"id":          idAttr("Mimecast DNS authentication outbound definition ID."),
		"description": requiredString("Definition description."),
		"domain":      requiredReplaceString("Domain associated with the definition."),
		"selector":    optionalComputedReplaceString("DKIM selector. Mimecast applies a default when omitted."),
		"sign_dkim":   optionalComputedBool("Whether to sign outbound messages with DKIM."),
		"key_length":  optionalComputedReplaceInt64("DKIM public key length, typically 1024 or 2048."),
		"dns_address": computedString("DNS address returned by Mimecast."),
		"public_key":  computedString("DKIM public key returned by Mimecast."),
		"validated":   schema.BoolAttribute{Description: "Whether the definition has been validated.", Computed: true},
	}}
}
func (r *dnsOutboundDefinitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = configureClient(req.ProviderData, resp)
	}
}
func (r *dnsOutboundDefinitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dnsOutboundDefinitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.client.CreateDNSOutboundDefinition(ctx, plan.toAPI())
	if err != nil {
		resp.Diagnostics.AddError("Unable to create DNS authentication outbound definition", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	created, err := r.client.GetDNSOutboundDefinition(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read created DNS authentication outbound definition", err.Error())
		return
	}
	plan.fromAPI(created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *dnsOutboundDefinitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dnsOutboundDefinitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetDNSOutboundDefinition(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read DNS authentication outbound definition", err.Error())
		return
	}
	state.fromAPI(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *dnsOutboundDefinitionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dnsOutboundDefinitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateDNSOutboundDefinition(ctx, plan.ID.ValueString(), plan.toAPI()); err != nil {
		resp.Diagnostics.AddError("Unable to update DNS authentication outbound definition", err.Error())
		return
	}
	updated, err := r.client.GetDNSOutboundDefinition(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read updated DNS authentication outbound definition", err.Error())
		return
	}
	plan.fromAPI(updated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *dnsOutboundDefinitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dnsOutboundDefinitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteDNSOutboundDefinition(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete DNS authentication outbound definition", err.Error())
	}
}
func (r *dnsOutboundDefinitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importIDPassthrough(ctx, req, resp)
}

func (m dnsOutboundDefinitionModel) toAPI() client.DNSOutboundDefinition {
	return client.DNSOutboundDefinition{
		ID: m.ID.ValueString(), Description: m.Description.ValueString(), Domain: m.Domain.ValueString(), Selector: m.Selector.ValueString(),
		SignDKIM: boolPtr(m.SignDKIM), KeyLength: m.KeyLength.ValueInt64(),
	}
}
func (m *dnsOutboundDefinitionModel) fromAPI(in client.DNSOutboundDefinition) {
	m.Description = stringValue(in.Description)
	m.Domain = stringValue(in.Domain)
	m.Selector = stringValue(in.Selector)
	m.SignDKIM = boolValue(in.SignDKIM)
	m.KeyLength = int64Value(in.KeyLength)
	m.DNSAddress = stringValue(in.DNSAddress)
	m.PublicKey = stringValue(in.PublicKey)
	m.Validated = boolValue(in.Validated)
}
