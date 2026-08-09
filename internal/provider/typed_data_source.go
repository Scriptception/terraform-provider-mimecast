package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type typedDataSource struct {
	typeName    string
	description string
	attributes  map[string]dsschema.Attribute
	read        func(context.Context, datasource.ReadRequest, *datasource.ReadResponse, *client.Client)
	client      *client.Client
}

func newTypedDataSource(typeName, description string, attributes map[string]dsschema.Attribute, read func(context.Context, datasource.ReadRequest, *datasource.ReadResponse, *client.Client)) datasource.DataSource {
	return &typedDataSource{typeName: typeName, description: description, attributes: attributes, read: read}
}

func (d *typedDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + d.typeName
}

func (d *typedDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dsschema.Schema{Description: d.description, Attributes: d.attributes}
}

func (d *typedDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.client = c
}

func (d *typedDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Mimecast API client is unavailable.")
		return
	}
	d.read(ctx, req, resp, d.client)
}

func dsID(description string) dsschema.StringAttribute {
	return dsschema.StringAttribute{Description: description, Computed: true}
}

func dsString(description string) dsschema.StringAttribute {
	return dsschema.StringAttribute{Description: description, Computed: true}
}

func dsRequiredString(description string) dsschema.StringAttribute {
	return dsschema.StringAttribute{Description: description, Required: true}
}

func dsSensitiveString(description string) dsschema.StringAttribute {
	return dsschema.StringAttribute{Description: description, Computed: true, Sensitive: true}
}

func dsBool(description string) dsschema.BoolAttribute {
	return dsschema.BoolAttribute{Description: description, Computed: true}
}

func dsInt64(description string) dsschema.Int64Attribute {
	return dsschema.Int64Attribute{Description: description, Computed: true}
}

func dsFloat64(description string) dsschema.Float64Attribute {
	return dsschema.Float64Attribute{Description: description, Computed: true}
}

func dsStringList(description string, sensitive bool) dsschema.ListAttribute {
	return dsschema.ListAttribute{Description: description, Computed: true, Sensitive: sensitive, ElementType: types.StringType}
}

func dsItems(attributes map[string]dsschema.Attribute) dsschema.ListNestedAttribute {
	return dsschema.ListNestedAttribute{Computed: true, NestedObject: dsschema.NestedAttributeObject{Attributes: attributes}}
}

type whoAmIModel struct {
	ID              types.String `tfsdk:"id"`
	Version         types.String `tfsdk:"version"`
	Type            types.String `tfsdk:"type"`
	AccountCodeCI   types.String `tfsdk:"account_code_ci"`
	AccountCodeCG   types.String `tfsdk:"account_code_cg"`
	AccountCodeX1   types.String `tfsdk:"account_code_x1"`
	AccountCodeLead types.String `tfsdk:"account_code_lead"`
	HomeCodeCI      types.String `tfsdk:"home_account_code_ci"`
	HomeCodeCG      types.String `tfsdk:"home_account_code_cg"`
	HomeCodeX1      types.String `tfsdk:"home_account_code_x1"`
	HomeCodeLead    types.String `tfsdk:"home_account_code_lead"`
}

func NewWhoamiDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable identity data source ID."), "version": dsString("Response contract version."), "type": dsString("Mimecast account type."),
		"account_code_ci": dsSensitiveString("Cloud Integrated target account code."), "account_code_cg": dsSensitiveString("Cloud Gateway target account code."),
		"account_code_x1": dsSensitiveString("X1 target account code."), "account_code_lead": dsSensitiveString("Lead target account code."),
		"home_account_code_ci": dsSensitiveString("Cloud Integrated home account code."), "home_account_code_cg": dsSensitiveString("Cloud Gateway home account code."),
		"home_account_code_x1": dsSensitiveString("X1 home account code."), "home_account_code_lead": dsSensitiveString("Lead home account code."),
	}
	return newTypedDataSource("whoami", "Read typed identity and account-code metadata for the current OAuth client.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.GetWhoAmI(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Mimecast identity", err.Error())
			return
		}
		state := whoAmIModel{ID: types.StringValue("whoami"), Version: stringValue(out.Version), Type: stringValue(out.Type), AccountCodeCI: stringValue(out.AccountCodes.CI), AccountCodeCG: stringValue(out.AccountCodes.CG), AccountCodeX1: stringValue(out.AccountCodes.X1), AccountCodeLead: stringValue(out.AccountCodes.Lead), HomeCodeCI: stringValue(out.HomeAccount.CI), HomeCodeCG: stringValue(out.HomeAccount.CG), HomeCodeX1: stringValue(out.HomeAccount.X1), HomeCodeLead: stringValue(out.HomeAccount.Lead)}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	})
}

type gatewayDetailsModel struct {
	ID                types.String                 `tfsdk:"id"`
	AccountCode       types.String                 `tfsdk:"account_code"`
	Region            types.String                 `tfsdk:"region"`
	ProtectionMode    types.String                 `tfsdk:"protection_mode"`
	Status            types.String                 `tfsdk:"status"`
	OutboundEnabled   types.Bool                   `tfsdk:"outbound_enabled"`
	OutboundHostnames types.List                   `tfsdk:"outbound_hostnames"`
	InboundMXRecords  *gatewayInboundMXRecordModel `tfsdk:"inbound_mx_records"`
	SPF               types.String                 `tfsdk:"spf"`
}

type gatewayInboundMXRecordModel struct {
	Hostname types.String  `tfsdk:"hostname"`
	Priority types.Float64 `tfsdk:"priority"`
}

func NewGatewayDetailsDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable data source ID."), "account_code": dsSensitiveString("Cloud Gateway account code."), "region": dsString("Mimecast region."), "protection_mode": dsString("Gateway protection mode."), "status": dsString("Gateway status."),
		"outbound_enabled": dsBool("Whether outbound mail flow is enabled."), "outbound_hostnames": dsStringList("Outbound mail hostnames.", false),
		"inbound_mx_records": dsschema.SingleNestedAttribute{Description: "Inbound mail-flow MX record.", Computed: true, Attributes: map[string]dsschema.Attribute{
			"hostname": dsString("Inbound MX hostname."), "priority": dsFloat64("Inbound MX priority."),
		}},
		"spf": dsString("SPF record for outbound mail."),
	}
	return newTypedDataSource("gateway_details", "Read typed Cloud Gateway account details.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.GetGatewayDetails(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read gateway details", err.Error())
			return
		}
		outboundHostnames, diags := listFromStrings(ctx, out.OutboundHostnames)
		resp.Diagnostics.Append(diags...)
		state := gatewayDetailsModel{ID: types.StringValue("gateway_details"), AccountCode: stringValue(out.AccountCode), Region: stringValue(out.Region), ProtectionMode: stringValue(out.ProtectionMode), Status: stringValue(out.Status), OutboundEnabled: boolValue(out.OutboundEnabled), OutboundHostnames: outboundHostnames, SPF: stringValue(out.SPF)}
		if out.InboundMXRecords != nil {
			state.InboundMXRecords = &gatewayInboundMXRecordModel{Hostname: stringValue(out.InboundMXRecords.Hostname), Priority: types.Float64Value(out.InboundMXRecords.Priority)}
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	})
}

type emergencyContactModel struct {
	ID                      types.String `tfsdk:"id"`
	AccountCode             types.String `tfsdk:"account_code"`
	ContactName             types.String `tfsdk:"contact_name"`
	ContactEmailAddress     types.String `tfsdk:"contact_email_address"`
	MobilePhone             types.String `tfsdk:"mobile_phone"`
	Telephone               types.String `tfsdk:"telephone"`
	AlternateEmailAddresses types.List   `tfsdk:"alternate_email_addresses"`
}

func NewEmergencyContactDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable data source ID."), "account_code": dsSensitiveString("Mimecast account code."), "contact_name": dsSensitiveString("Emergency contact name."), "contact_email_address": dsSensitiveString("Emergency contact email address."), "mobile_phone": dsSensitiveString("Emergency mobile number."), "telephone": dsSensitiveString("Emergency telephone number."), "alternate_email_addresses": dsStringList("Alternate emergency email addresses.", true)}
	return newTypedDataSource("emergency_contact", "Read the typed Cloud Gateway emergency-contact configuration. Mutation is excluded because the API has no safe delete or reset lifecycle.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.GetEmergencyContact(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read emergency contact", err.Error())
			return
		}
		alternates, diags := listFromStrings(ctx, out.AlternateEmailAddresses)
		resp.Diagnostics.Append(diags...)
		state := emergencyContactModel{ID: types.StringValue("emergency_contact"), AccountCode: stringValue(out.AccountCode), ContactName: stringValue(out.ContactName), ContactEmailAddress: stringValue(out.ContactEmailAddress), MobilePhone: stringValue(out.MobilePhone), Telephone: stringValue(out.Telephone), AlternateEmailAddresses: alternates}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	})
}

type accountModel struct {
	ID                              types.String `tfsdk:"id"`
	AccountCode                     types.String `tfsdk:"account_code"`
	AccountName                     types.String `tfsdk:"account_name"`
	MimecastID                      types.String `tfsdk:"mimecast_id"`
	Region                          types.String `tfsdk:"region"`
	Type                            types.String `tfsdk:"type"`
	MailPlatform                    types.String `tfsdk:"mail_platform"`
	Gateway                         types.Bool   `tfsdk:"gateway"`
	Archive                         types.Bool   `tfsdk:"archive"`
	PolicyInheritance               types.Bool   `tfsdk:"policy_inheritance"`
	MaxRetention                    types.Int64  `tfsdk:"max_retention"`
	MinRetentionEnabled             types.Bool   `tfsdk:"min_retention_enabled"`
	UserCount                       types.Int64  `tfsdk:"user_count"`
	Packages                        types.List   `tfsdk:"packages"`
	CybergraphV2Enabled             types.Bool   `tfsdk:"cybergraph_v2_enabled"`
	ExportAPI                       types.Bool   `tfsdk:"export_api"`
	AutomatedSegmentPurge           types.Bool   `tfsdk:"automated_segment_purge"`
	AdminSessionTimeout             types.Int64  `tfsdk:"admin_session_timeout"`
	ContentAdministratorDefaultView types.String `tfsdk:"content_administrator_default_view"`
	ExgestAllowExtraction           types.Bool   `tfsdk:"exgest_allow_extraction"`
	ExgestAllowQuery                types.Bool   `tfsdk:"exgest_allow_query"`
	ExpressAccount                  types.Bool   `tfsdk:"express_account"`
	MaxRetentionConfirmed           types.Bool   `tfsdk:"max_retention_confirmed"`
	SearchReason                    types.Bool   `tfsdk:"search_reason"`
}

func NewAccountDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable account data source ID."), "account_code": dsSensitiveString("Mimecast account code."), "account_name": dsString("Account name."), "mimecast_id": dsSensitiveString("Mimecast account ID."),
		"region": dsString("Hosting region."), "type": dsString("Account type."), "mail_platform": dsString("Configured mail platform."), "gateway": dsBool("Whether Cloud Gateway is enabled."),
		"archive": dsBool("Whether archive features are enabled."), "policy_inheritance": dsBool("Whether policy inheritance is enabled."), "max_retention": dsInt64("Maximum retention in days."),
		"min_retention_enabled": dsBool("Whether minimum retention is enabled."), "user_count": dsInt64("Licensed user count."), "packages": dsStringList("Enabled account package names.", false),
		"cybergraph_v2_enabled": dsBool("Whether CyberGraph v2 is enabled."), "export_api": dsBool("Whether export API features are enabled."), "automated_segment_purge": dsBool("Whether automated segment purge is enabled."),
		"admin_session_timeout": dsInt64("Administrator session timeout in minutes."), "content_administrator_default_view": dsString("Default view for content administrators."),
		"exgest_allow_extraction": dsBool("Whether data extraction operations are allowed."), "exgest_allow_query": dsBool("Whether data-ingestion query operations are allowed."),
		"express_account": dsBool("Whether this is an express account."), "max_retention_confirmed": dsBool("Whether maximum retention has been confirmed."), "search_reason": dsBool("Whether search-reason auditing is enabled."),
	}
	return newTypedDataSource("account", "Read a safe typed account summary. Contact details, support passphrases, and other secrets are deliberately excluded.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.GetAccountSummary(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read account summary", err.Error())
			return
		}
		packages := make([]string, 0, len(out.Packages))
		for _, item := range out.Packages {
			packages = append(packages, string(item))
		}
		packageList, diags := listFromStrings(ctx, packages)
		resp.Diagnostics.Append(diags...)
		state := accountModel{ID: types.StringValue("account"), AccountCode: stringValue(out.AccountCode), AccountName: stringValue(out.AccountName), MimecastID: stringValue(out.MimecastID), Region: stringValue(out.Region), Type: stringValue(out.Type), MailPlatform: stringValue(out.MailPlatform), Gateway: boolValue(out.Gateway), Archive: boolValue(out.Archive), PolicyInheritance: boolValue(out.PolicyInheritance), MaxRetention: types.Int64Value(out.MaxRetention), MinRetentionEnabled: boolValue(out.MinRetentionEnabled), UserCount: types.Int64Value(out.UserCount), Packages: packageList, CybergraphV2Enabled: boolValue(out.CybergraphV2Enabled), ExportAPI: boolValue(out.ExportAPI), AutomatedSegmentPurge: boolValue(out.AutomatedSegmentPurge), AdminSessionTimeout: types.Int64Value(out.AdminSessionTimeout), ContentAdministratorDefaultView: stringValue(out.ContentAdministratorDefaultView), ExgestAllowExtraction: boolValue(out.ExgestAllowExtraction), ExgestAllowQuery: boolValue(out.ExgestAllowQuery), ExpressAccount: boolValue(out.ExpressAccount), MaxRetentionConfirmed: boolValue(out.MaxRetentionConfirmed), SearchReason: boolValue(out.SearchReason)}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	})
}

type packageItemModel struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
}

type packagesModel struct {
	ID    types.String       `tfsdk:"id"`
	Items []packageItemModel `tfsdk:"items"`
}

func NewAccountPackagesDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable package inventory ID."), "items": dsItems(map[string]dsschema.Attribute{"id": dsID("Product ID."), "name": dsString("Product name.")})}
	return newTypedDataSource("account_packages", "Read the provisioned Mimecast product/package inventory.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListProvisionedPackages(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read account packages", err.Error())
			return
		}
		items := make([]packageItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, packageItemModel{ID: stringValue(item.Products.ID), Name: stringValue(item.Products.Name)})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &packagesModel{ID: types.StringValue("account_packages"), Items: items})...)
	})
}

type domainItemModel struct {
	ID              types.String `tfsdk:"id"`
	Domain          types.String `tfsdk:"domain"`
	Local           types.Bool   `tfsdk:"local"`
	SendOnly        types.Bool   `tfsdk:"send_only"`
	InboundType     types.String `tfsdk:"inbound_type"`
	CreatedDateTime types.String `tfsdk:"created_date_time"`
	ExpiryDateTime  types.String `tfsdk:"expiry_date_time"`
}

type domainsModel struct {
	ID    types.String      `tfsdk:"id"`
	Items []domainItemModel `tfsdk:"items"`
}

func domainAttributes() map[string]dsschema.Attribute {
	return map[string]dsschema.Attribute{"id": dsID("Domain ID."), "domain": dsString("Domain name."), "local": dsBool("Whether the domain is local."), "send_only": dsBool("Whether the domain is send-only."), "inbound_type": dsString("Inbound validation mode."), "created_date_time": dsString("Pending-domain creation time."), "expiry_date_time": dsString("Pending-domain verification expiry time.")}
}

func NewInternalDomainsDataSource() datasource.DataSource {
	return newDomainDataSource("internal_domains", "Read all internal domains with cursor pagination.", func(ctx context.Context, c *client.Client) ([]domainItemModel, error) {
		out, err := c.ListInternalDomains(ctx)
		items := make([]domainItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, domainItemModel{ID: stringValue(item.ID), Domain: stringValue(item.Domain), Local: boolValue(item.Local), SendOnly: boolValue(item.SendOnly), InboundType: stringValue(item.InboundType), CreatedDateTime: types.StringNull(), ExpiryDateTime: types.StringNull()})
		}
		return items, err
	})
}

func NewExternalDomainsDataSource() datasource.DataSource {
	return newDomainDataSource("external_domains", "Read all external domains with cursor pagination.", func(ctx context.Context, c *client.Client) ([]domainItemModel, error) {
		out, err := c.ListExternalDomains(ctx)
		items := make([]domainItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, domainItemModel{ID: stringValue(item.ID), Domain: stringValue(item.Domain), Local: types.BoolNull(), SendOnly: types.BoolNull(), InboundType: types.StringNull(), CreatedDateTime: types.StringNull(), ExpiryDateTime: types.StringNull()})
		}
		return items, err
	})
}

func NewPendingDomainsDataSource() datasource.DataSource {
	return newDomainDataSource("pending_domains", "Read all pending domains with cursor pagination. Verification tokens are deliberately excluded from Terraform state.", func(ctx context.Context, c *client.Client) ([]domainItemModel, error) {
		out, err := c.ListPendingDomains(ctx)
		items := make([]domainItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, domainItemModel{ID: stringValue(item.ID), Domain: stringValue(item.Domain), Local: boolValue(item.Local), SendOnly: boolValue(item.SendOnly), InboundType: stringValue(item.InboundType), CreatedDateTime: stringValue(item.CreatedDateTime), ExpiryDateTime: stringValue(item.ExpiryDateTime)})
		}
		return items, err
	})
}

func newDomainDataSource(typeName, description string, load func(context.Context, *client.Client) ([]domainItemModel, error)) datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(domainAttributes())}
	return newTypedDataSource(typeName, description, attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		items, err := load(ctx, c)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Mimecast domains", err.Error())
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &domainsModel{ID: types.StringValue(typeName), Items: items})...)
	})
}

type profileGroupsModel struct {
	ID    types.String        `tfsdk:"id"`
	Items []profileGroupModel `tfsdk:"items"`
}

func NewProfileGroupsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{"id": dsID("Profile group ID."), "description": dsString("Group description."), "parent_id": dsString("Parent group ID."), "source": dsString("Group source."), "user_count": dsInt64("Direct user count."), "group_count": dsInt64("Child group count.")}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("profile_groups", "Read all profile groups with cursor pagination and deterministic ordering.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListProfileGroups(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read profile groups", err.Error())
			return
		}
		items := make([]profileGroupModel, 0, len(out))
		for _, item := range out {
			model := profileGroupModel{ID: stringValue(item.ID)}
			model.fromAPI(item)
			items = append(items, model)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &profileGroupsModel{ID: types.StringValue("profile_groups"), Items: items})...)
	})
}

type userItemModel struct {
	ID              types.String `tfsdk:"id"`
	EmailAddress    types.String `tfsdk:"email_address"`
	Name            types.String `tfsdk:"name"`
	Domain          types.String `tfsdk:"domain"`
	Type            types.String `tfsdk:"type"`
	Internal        types.Bool   `tfsdk:"internal"`
	Disabled        types.Bool   `tfsdk:"disabled"`
	CreatedDateTime types.String `tfsdk:"created_date_time"`
	UpdatedDateTime types.String `tfsdk:"updated_date_time"`
	AddressType     types.String `tfsdk:"address_type"`
	IsAlias         types.Bool   `tfsdk:"is_alias"`
}

type usersModel struct {
	ID    types.String    `tfsdk:"id"`
	Items []userItemModel `tfsdk:"items"`
}

func NewUsersDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{"id": dsID("User ID."), "email_address": dsSensitiveString("User email address."), "name": dsString("Display name."), "domain": dsString("Parent domain."), "type": dsString("Directory user type."), "internal": dsBool("Whether the user is internal."), "disabled": dsBool("Whether the user is disabled."), "created_date_time": dsString("Creation timestamp."), "updated_date_time": dsString("Last update timestamp."), "address_type": dsString("Mimecast address type."), "is_alias": dsBool("Whether the user is an alias.")}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable user inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("users", "Read all directory users with cursor pagination. Email addresses are marked sensitive in Terraform output.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListUsers(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read users", err.Error())
			return
		}
		items := make([]userItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, userItemModel{ID: stringValue(item.ID), EmailAddress: stringValue(item.EmailAddress), Name: stringValue(item.Name), Domain: stringValue(item.Domain), Type: stringValue(item.Type), Internal: boolValue(item.Internal), Disabled: boolValue(item.Disabled), CreatedDateTime: stringValue(item.CreatedDateTime), UpdatedDateTime: stringValue(item.UpdatedDateTime), AddressType: stringValue(item.AddressType), IsAlias: boolValue(item.IsAlias)})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &usersModel{ID: types.StringValue("users"), Items: items})...)
	})
}

type roleItemModel struct {
	ID       types.String `tfsdk:"id"`
	RoleName types.String `tfsdk:"role_name"`
}

type rolesModel struct {
	ID    types.String    `tfsdk:"id"`
	Items []roleItemModel `tfsdk:"items"`
}

func NewRolesDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable role inventory ID."), "items": dsItems(map[string]dsschema.Attribute{"id": dsID("Role ID."), "role_name": dsString("Role name.")})}
	return newTypedDataSource("roles", "Read all account roles with cursor pagination. This requires Directories | Roles | Read.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListRoles(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read roles", err.Error())
			return
		}
		items := make([]roleItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, roleItemModel{ID: stringValue(item.ID), RoleName: stringValue(item.RoleName)})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &rolesModel{ID: types.StringValue("roles"), Items: items})...)
	})
}

type groupMemberItemModel struct {
	EmailAddress types.String `tfsdk:"email_address"`
	Domain       types.String `tfsdk:"domain"`
	Name         types.String `tfsdk:"name"`
	Internal     types.Bool   `tfsdk:"internal"`
	Type         types.String `tfsdk:"type"`
	Note         types.String `tfsdk:"note"`
}

type groupMembersModel struct {
	ID      types.String           `tfsdk:"id"`
	GroupID types.String           `tfsdk:"group_id"`
	Items   []groupMemberItemModel `tfsdk:"items"`
}

func NewProfileGroupMembersDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable inventory ID."), "group_id": dsRequiredString("Profile group ID."),
		"items": dsItems(map[string]dsschema.Attribute{"email_address": dsSensitiveString("Member email address."), "domain": dsString("Member domain."), "name": dsString("Member display name."), "internal": dsBool("Whether the member is internal."), "type": dsString("Member type."), "note": dsString("Member note.")}),
	}
	return newTypedDataSource("profile_group_members", "Read all members of one profile group with cursor pagination.", attrs, func(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		var config groupMembersModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
		if resp.Diagnostics.HasError() {
			return
		}
		out, err := c.ListProfileGroupMembers(ctx, config.GroupID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to read profile group members", err.Error())
			return
		}
		items := make([]groupMemberItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, groupMemberItemFromAPI(item))
		}
		config.ID = types.StringValue("profile_group_members/" + config.GroupID.ValueString())
		config.Items = items
		resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
	})
}

func groupMemberItemFromAPI(item client.GroupMember) groupMemberItemModel {
	return groupMemberItemModel{
		EmailAddress: stringValue(item.EmailAddress), Domain: stringValue(item.Domain), Name: stringValue(item.Name),
		Internal: boolValue(item.Internal), Type: stringValue(item.Type), Note: stringValue(item.Note),
	}
}

type deliveryRouteDefinitionItemModel struct {
	ID               types.String `tfsdk:"id"`
	Description      types.String `tfsdk:"description"`
	Hostname         types.String `tfsdk:"hostname"`
	Port             types.Int64  `tfsdk:"port"`
	AlternateRouteID types.String `tfsdk:"alternate_route_id"`
	AuthMechanisms   types.List   `tfsdk:"auth_mechanisms"`
	Username         types.String `tfsdk:"username"`
	Domain           types.String `tfsdk:"domain"`
}

type deliveryRouteDefinitionsModel struct {
	ID    types.String                       `tfsdk:"id"`
	Items []deliveryRouteDefinitionItemModel `tfsdk:"items"`
}

func NewDeliveryRouteDefinitionsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{"id": dsID("Definition ID."), "description": dsString("Description."), "hostname": dsString("Destination host."), "port": dsInt64("Destination port."), "alternate_route_id": dsString("Alternate route ID."), "auth_mechanisms": dsStringList("SMTP authentication mechanisms.", false), "username": dsSensitiveString("SMTP authentication username."), "domain": dsString("SMTP authentication domain.")}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("delivery_route_definitions", "Read all delivery route definitions with cursor pagination. Authentication passwords are never returned or stored.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListDeliveryRouteDefinitions(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read delivery route definitions", err.Error())
			return
		}
		items := make([]deliveryRouteDefinitionItemModel, 0, len(out))
		for _, item := range out {
			mechs, username, domain := deliveryRouteAuthenticationFromAPI(item)
			list, diags := listFromStrings(ctx, mechs)
			resp.Diagnostics.Append(diags...)
			items = append(items, deliveryRouteDefinitionItemModel{ID: stringValue(item.ID), Description: stringValue(item.Description), Hostname: stringValue(item.Hostname), Port: types.Int64Value(item.Port), AlternateRouteID: stringValue(item.AlternateRouteID), AuthMechanisms: list, Username: stringValue(username), Domain: stringValue(domain)})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &deliveryRouteDefinitionsModel{ID: types.StringValue("delivery_route_definitions"), Items: items})...)
	})
}

type dnsDefinitionItemModel struct {
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

type dnsDefinitionsModel struct {
	ID    types.String             `tfsdk:"id"`
	Items []dnsDefinitionItemModel `tfsdk:"items"`
}

func NewDNSAuthenticationOutboundDefinitionsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{"id": dsID("Definition ID."), "description": dsString("Description."), "domain": dsString("Signing domain."), "selector": dsString("DKIM selector."), "sign_dkim": dsBool("Whether DKIM signing is enabled."), "key_length": dsInt64("DKIM key length."), "dns_address": dsString("DNS record address."), "public_key": dsString("Public DKIM key."), "validated": dsBool("Whether the definition is validated.")}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("dns_authentication_outbound_definitions", "Read all DNS authentication outbound definitions with cursor pagination.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListDNSOutboundDefinitions(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read DNS outbound definitions", err.Error())
			return
		}
		items := make([]dnsDefinitionItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, dnsDefinitionItemModel{ID: stringValue(item.ID), Description: stringValue(item.Description), Domain: stringValue(item.Domain), Selector: stringValue(item.Selector), SignDKIM: boolValue(item.SignDKIM), KeyLength: types.Int64Value(item.KeyLength), DNSAddress: stringValue(item.DNSAddress), PublicKey: stringValue(item.PublicKey), Validated: boolValue(item.Validated)})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dnsDefinitionsModel{ID: types.StringValue("dns_authentication_outbound_definitions"), Items: items})...)
	})
}

type managedURLsModel struct {
	ID                       types.String      `tfsdk:"id"`
	Items                    []managedURLModel `tfsdk:"items"`
	ExcludedAccessTokenCount types.Int64       `tfsdk:"excluded_access_token_count"`
}

func NewManagedURLsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{"id": dsID("Managed URL ID."), "url": dsString("Managed URL or domain."), "action": dsString("Block or permit action."), "match_type": dsString("Explicit or domain match."), "comment": dsString("Tracking comment."), "disable_log_click": dsBool("Whether click logging is disabled."), "disable_rewrite": dsBool("Whether URL rewriting is disabled."), "disable_user_awareness": dsBool("Whether awareness challenges are disabled.")}
	attrs := map[string]dsschema.Attribute{
		"id":                          dsID("Stable inventory ID."),
		"items":                       dsItems(itemAttrs),
		"excluded_access_token_count": dsInt64("Number of whole managed URL records excluded because their decoded query parameter name is access_token."),
	}
	return newTypedDataSource("managed_urls", "Read supported Targeted Threat Protection managed URLs with token pagination and ID-stable ordering. Records whose decoded query parameter name is access_token are excluded before state mapping and counted separately.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListManagedURLs(ctx, "", false)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read managed URLs", err.Error())
			return
		}
		items := make([]managedURLModel, 0, len(out))
		var excluded int64
		for _, item := range out {
			if client.ManagedURLHasAccessTokenQuery(item) {
				excluded++
				continue
			}
			model := managedURLModel{}
			if !model.fromAPI(item) {
				excluded++
				continue
			}
			items = append(items, model)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &managedURLsModel{ID: types.StringValue("managed_urls"), Items: items, ExcludedAccessTokenCount: types.Int64Value(excluded)})...)
	})
}

type journalingItemModel struct {
	ID                              types.String `tfsdk:"id"`
	Description                     types.String `tfsdk:"description"`
	Enabled                         types.Bool   `tfsdk:"enabled"`
	MessageFormat                   types.String `tfsdk:"message_format"`
	RemoveJournalHeaders            types.Bool   `tfsdk:"remove_journal_headers"`
	JournalNonInternalAddresses     types.Bool   `tfsdk:"journal_non_internal_addresses"`
	JournalUnknownInternalAddresses types.Bool   `tfsdk:"journal_unknown_internal_addresses"`
	TransferProtocol                types.String `tfsdk:"transfer_protocol"`
	Status                          types.String `tfsdk:"status"`
	LastReceivedDateTime            types.String `tfsdk:"last_received_date_time"`
	QueueSize                       types.Int64  `tfsdk:"queue_size"`
	SMTPEmailAddress                types.String `tfsdk:"smtp_email_address"`
	SMTPIPRanges                    types.List   `tfsdk:"smtp_ip_ranges"`
	SMTPUsesAuthentication          types.Bool   `tfsdk:"smtp_uses_authentication"`
	SMTPUsesTLS                     types.Bool   `tfsdk:"smtp_uses_tls"`
	SMTPPrefersClearText            types.Bool   `tfsdk:"smtp_prefers_clear_text"`
	SMTPExtendedDeduplication       types.Bool   `tfsdk:"smtp_extended_deduplication"`
	SMTPDeliveryWaitAttempts        types.Int64  `tfsdk:"smtp_delivery_wait_attempts"`
	SMTPInactivityTimeout           types.Int64  `tfsdk:"smtp_inactivity_timeout"`
	SMTPProcessInitialDelay         types.Int64  `tfsdk:"smtp_process_initial_delay"`
	SMTPHostnames                   types.List   `tfsdk:"smtp_hostnames"`
	POP3EmailAddress                types.String `tfsdk:"pop3_email_address"`
	POP3Mailbox                     types.String `tfsdk:"pop3_mailbox"`
	POP3Host                        types.String `tfsdk:"pop3_host"`
	POP3Port                        types.Int64  `tfsdk:"pop3_port"`
	POP3UsesPOP3S                   types.Bool   `tfsdk:"pop3_uses_pop3s"`
	POP3EncryptionIsRelaxed         types.Bool   `tfsdk:"pop3_encryption_is_relaxed"`
	POP3DetailedLoggingIsEnabled    types.Bool   `tfsdk:"pop3_detailed_logging_is_enabled"`
}

type journalingServicesModel struct {
	ID    types.String          `tfsdk:"id"`
	Items []journalingItemModel `tfsdk:"items"`
}

func NewJournalingServicesDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{
		"id": dsID("Journaling service ID."), "description": dsString("Description."), "enabled": dsBool("Whether the service is enabled."), "message_format": dsString("Journal message format."),
		"remove_journal_headers": dsBool("Whether Exchange journal headers are removed."), "journal_non_internal_addresses": dsBool("Whether non-internal addresses are journalled."),
		"journal_unknown_internal_addresses": dsBool("Whether unknown internal addresses are journalled."), "transfer_protocol": dsString("Transfer protocol."),
		"status": dsString("Service status."), "last_received_date_time": dsString("Time the last journal message was received."), "queue_size": dsInt64("Current queue size."),
		"smtp_email_address": dsSensitiveString("SMTP journaling email address."), "smtp_ip_ranges": dsStringList("Permitted SMTP source IP ranges.", false),
		"smtp_uses_authentication": dsBool("Whether SMTP authentication is used."), "smtp_uses_tls": dsBool("Whether SMTP uses TLS."), "smtp_prefers_clear_text": dsBool("Whether clear text is preferred."),
		"smtp_extended_deduplication": dsBool("Whether extended deduplication is enabled."), "smtp_delivery_wait_attempts": dsInt64("Delivery wait attempts."),
		"smtp_inactivity_timeout": dsInt64("SMTP inactivity timeout."), "smtp_process_initial_delay": dsInt64("SMTP process initial delay."), "smtp_hostnames": dsStringList("SMTP connector hostnames.", false),
		"pop3_email_address": dsSensitiveString("POP3 journaling email address."), "pop3_mailbox": dsSensitiveString("POP3 mailbox username."), "pop3_host": dsString("POP3 server host."),
		"pop3_port": dsInt64("POP3 server port."), "pop3_uses_pop3s": dsBool("Whether POP3S is used."), "pop3_encryption_is_relaxed": dsBool("Whether relaxed POP3 certificate validation is enabled."),
		"pop3_detailed_logging_is_enabled": dsBool("Whether detailed POP3 logging is enabled."),
	}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("journaling_services", "Read all journaling services with cursor pagination, including every non-secret connection and status field. Passwords are never decoded into this surface.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListJournalingServices(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read journaling services", err.Error())
			return
		}
		items := make([]journalingItemModel, 0, len(out))
		for _, item := range out {
			model := journalingItemModel{
				ID: pointerStringValue(item.ID), Description: pointerStringValue(item.Description), Enabled: boolValue(item.Enabled), MessageFormat: pointerStringValue(item.MessageFormat),
				RemoveJournalHeaders: boolValue(item.RemoveJournalHeaders), JournalNonInternalAddresses: boolValue(item.JournalNonInternalAddresses),
				JournalUnknownInternalAddresses: boolValue(item.JournalUnknownInternalAddresses), TransferProtocol: pointerStringValue(item.TransferProtocol), QueueSize: pointerInt64Value(item.QueueSize),
				SMTPIPRanges: types.ListNull(types.StringType), SMTPHostnames: types.ListNull(types.StringType),
			}
			if item.StatusInfo != nil {
				model.Status = pointerStringValue(item.StatusInfo.Status)
				model.LastReceivedDateTime = pointerStringValue(item.StatusInfo.LastReceivedDateTime)
			}
			if connection := item.SMTPJournalingConnection; connection != nil {
				model.SMTPEmailAddress = pointerStringValue(connection.EmailAddress)
				model.SMTPIPRanges = pointerStringListValue(ctx, connection.IPRanges, &resp.Diagnostics)
				model.SMTPUsesAuthentication = boolValue(connection.UsesAuthentication)
				model.SMTPUsesTLS = boolValue(connection.UsesTLS)
				model.SMTPPrefersClearText = boolValue(connection.PrefersClearText)
				model.SMTPExtendedDeduplication = boolValue(connection.ExtendedDeduplication)
				model.SMTPDeliveryWaitAttempts = pointerInt64Value(connection.DeliveryWaitAttempts)
				model.SMTPInactivityTimeout = pointerInt64Value(connection.InactivityTimeout)
				model.SMTPProcessInitialDelay = pointerInt64Value(connection.ProcessInitialDelay)
				model.SMTPHostnames = pointerStringListValue(ctx, connection.Hostnames, &resp.Diagnostics)
			}
			if connection := item.POP3JournalingConnection; connection != nil {
				model.POP3EmailAddress = pointerStringValue(connection.EmailAddress)
				model.POP3Mailbox = pointerStringValue(connection.Mailbox)
				model.POP3Host = pointerStringValue(connection.Host)
				model.POP3Port = pointerInt64Value(connection.Port)
				model.POP3UsesPOP3S = boolValue(connection.UsesPOP3S)
				model.POP3EncryptionIsRelaxed = boolValue(connection.EncryptionIsRelaxed)
				model.POP3DetailedLoggingIsEnabled = boolValue(connection.DetailedLoggingIsEnabled)
			}
			items = append(items, model)
		}
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &journalingServicesModel{ID: types.StringValue("journaling_services"), Items: items})...)
	})
}

func pointerStringValue(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return stringValue(*value)
}

func pointerInt64Value(value *int64) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*value)
}

func pointerStringListValue(ctx context.Context, value *[]string, diags *diag.Diagnostics) types.List {
	if value == nil {
		return types.ListNull(types.StringType)
	}
	list, listDiags := listFromStrings(ctx, *value)
	diags.Append(listDiags...)
	return list
}

type connectorItemModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	ProductID          types.String `tfsdk:"product_id"`
	ProductName        types.String `tfsdk:"product_name"`
	ProductCode        types.String `tfsdk:"product_code"`
	ProductDescription types.String `tfsdk:"product_description"`
	ConnectorProvider  types.String `tfsdk:"connector_provider"`
	Status             types.String `tfsdk:"status"`
	CreatedDateTime    types.String `tfsdk:"created_date_time"`
	UpdatedDateTime    types.String `tfsdk:"updated_date_time"`
}

type connectorsModel struct {
	ID    types.String         `tfsdk:"id"`
	Items []connectorItemModel `tfsdk:"items"`
}

func NewConnectorsDataSource() datasource.DataSource {
	itemAttrs := map[string]dsschema.Attribute{"id": dsID("Connector ID."), "name": dsString("Connector name."), "description": dsString("Description."), "product_id": dsString("Product ID."), "product_name": dsString("Product name."), "product_code": dsString("Product code."), "product_description": dsString("Product description."), "connector_provider": dsString("Connector provider."), "status": dsString("Consent or connection status."), "created_date_time": dsString("Creation timestamp."), "updated_date_time": dsString("Last update timestamp.")}
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(itemAttrs)}
	return newTypedDataSource("connectors", "Read all connectors with cursor pagination. Connector consent is intentionally not modelled as a resource lifecycle.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListConnectors(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read connectors", err.Error())
			return
		}
		items := make([]connectorItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, connectorItemModel{ID: stringValue(item.ID), Name: stringValue(item.Name), Description: stringValue(item.Description), ProductID: stringValue(item.Product.ID), ProductName: stringValue(item.Product.Name), ProductCode: stringValue(item.Product.Code), ProductDescription: stringValue(item.Product.Description), ConnectorProvider: stringValue(item.Provider), Status: stringValue(item.Status), CreatedDateTime: stringValue(item.CreatedDateTime), UpdatedDateTime: stringValue(item.UpdatedDateTime)})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &connectorsModel{ID: types.StringValue("connectors"), Items: items})...)
	})
}

func canonicalFingerprint(value any) types.String {
	data, err := client.CanonicalJSON(value)
	if err != nil {
		return types.StringNull()
	}
	sum := sha256.Sum256(data)
	return types.StringValue(hex.EncodeToString(sum[:]))
}

func NewCloudIntegratedDefaultPolicyDataSource() datasource.DataSource {
	return newTypedDataSource("cloud_integrated_default_policy", "Read the complete typed Cloud Integrated default-policy contract with canonical semantic fingerprints.", cloudIntegratedDefaultDataSourceAttributes(), func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.GetCloudIntegratedDefaultPolicy(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Cloud Integrated default policy", err.Error())
			return
		}
		state := cloudIntegratedPolicyModel{}
		state.fromAPI(ctx, out, &resp.Diagnostics)
		state.ID = types.StringValue("cloud_integrated_default_policy")
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	})
}

type policiesModel struct {
	ID    types.String  `tfsdk:"id"`
	Items []policyModel `tfsdk:"items"`
}

func policyInventoryAttributes() map[string]dsschema.Attribute {
	return map[string]dsschema.Attribute{
		"id": dsID("Policy ID."), "description": dsString("Description."), "option": dsString("Policy option."), "definition_id": dsString("Referenced definition ID."), "from_part": dsString("Sender part."),
		"from_type": dsString("Source target type."), "from_group_id": dsString("Source group ID."), "from_domain": dsString("Source domain."), "from_email_address": dsSensitiveString("Source email address."), "from_attribute_id": dsString("Source attribute ID."), "from_attribute_value": dsString("Source attribute value."),
		"to_type": dsString("Destination target type."), "to_group_id": dsString("Destination group ID."), "to_domain": dsString("Destination domain."), "to_email_address": dsSensitiveString("Destination email address."), "to_attribute_id": dsString("Destination attribute ID."), "to_attribute_value": dsString("Destination attribute value."),
		"enabled": dsBool("Whether enabled."), "enforced": dsBool("Whether enforced."), "override": dsBool("Whether overrides lower-priority matches."), "bidirectional": dsBool("Whether bidirectional."), "from_eternal": dsBool("Whether source schedule is eternal."), "to_eternal": dsBool("Whether destination schedule is eternal."), "from_date_time": dsString("Source schedule value."), "to_date_time": dsString("Destination schedule value."),
		"source_ips": dsStringList("Source IP conditions.", false), "hostnames": dsStringList("Hostname conditions.", false), "spf_domains": dsStringList("SPF-domain conditions.", false),
	}
}

func newPolicyInventoryDataSource(kind, typeName, description string) datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable inventory ID."), "items": dsItems(policyInventoryAttributes())}
	return newTypedDataSource(typeName, description, attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListPolicies(ctx, kind)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Mimecast policies", err.Error())
			return
		}
		items := make([]policyModel, 0, len(out))
		for _, item := range out {
			model := policyModel{}
			model.fromAPI(ctx, item, &resp.Diagnostics)
			items = append(items, model)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &policiesModel{ID: types.StringValue(typeName), Items: items})...)
	})
}

func NewGreylistingPoliciesDataSource() datasource.DataSource {
	return newPolicyInventoryDataSource("greylisting", "greylisting_policies", "Read all greylisting policies with cursor pagination.")
}

func NewDeliveryRoutePoliciesDataSource() datasource.DataSource {
	return newPolicyInventoryDataSource("delivery_route", "delivery_route_policies", "Read all delivery route policies with cursor pagination.")
}

func NewAntiSpoofingPoliciesDataSource() datasource.DataSource {
	return newPolicyInventoryDataSource("anti_spoofing", "anti_spoofing_policies", "Read all anti-spoofing policies, accepting documented and observed response wrappers.")
}

func NewAntiSpoofingBypassPoliciesDataSource() datasource.DataSource {
	return newPolicyInventoryDataSource("anti_spoofing_bypass", "anti_spoofing_bypass_policies", "Read all anti-spoofing bypass policies with cursor pagination.")
}

func NewBlockedSenderPoliciesDataSource() datasource.DataSource {
	return newPolicyInventoryDataSource("blocked_sender", "blocked_sender_policies", "Read all blocked sender policies with cursor pagination.")
}

func NewDNSAuthenticationOutboundPoliciesDataSource() datasource.DataSource {
	return newPolicyInventoryDataSource("dns_authentication_outbound", "dns_authentication_outbound_policies", "Read all DNS authentication outbound policies with cursor pagination.")
}

type outboundIPAddressesDataModel struct {
	ID                  types.String `tfsdk:"id"`
	OutboundIPAddresses types.Set    `tfsdk:"outbound_ip_addresses"`
}

func NewOutboundIPAddressesDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{"id": dsID("Stable data source ID."), "outbound_ip_addresses": dsschema.SetAttribute{Description: "Canonical account outbound IP address set.", Computed: true, ElementType: types.StringType}}
	return newTypedDataSource("outbound_ip_addresses", "Read the canonical account-level outbound IP address set.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.GetOutboundIPAddresses(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read outbound IP addresses", err.Error())
			return
		}
		sort.Strings(out)
		set, diags := setFromStrings(ctx, out)
		resp.Diagnostics.Append(diags...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &outboundIPAddressesDataModel{ID: types.StringValue("outbound_ip_addresses"), OutboundIPAddresses: set})...)
	})
}
