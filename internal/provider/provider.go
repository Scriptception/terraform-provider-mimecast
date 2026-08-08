package provider

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

var _ provider.Provider = (*MimecastProvider)(nil)

type MimecastProvider struct{ version string }

type providerModel struct {
	BaseURL         types.String `tfsdk:"base_url"`
	TokenURL        types.String `tfsdk:"token_url"`
	ClientID        types.String `tfsdk:"client_id"`
	ClientSecret    types.String `tfsdk:"client_secret"`
	TokenAuthMethod types.String `tfsdk:"token_auth_method"`
	Scopes          types.List   `tfsdk:"scopes"`
	Insecure        types.Bool   `tfsdk:"insecure"`
	TimeoutSeconds  types.Int64  `tfsdk:"timeout_seconds"`
	MaxRetries      types.Int64  `tfsdk:"max_retries"`
	PageSize        types.Int64  `tfsdk:"page_size"`
	ReadOnly        types.Bool   `tfsdk:"read_only"`
	ProxyURL        types.String `tfsdk:"proxy_url"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &MimecastProvider{version: version} }
}

func (p *MimecastProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "mimecast"
	resp.Version = p.version
}

func (p *MimecastProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage durable Mimecast administration configuration as code. This provider is unofficial and is not affiliated with or endorsed by Mimecast.",
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				Description: "Base URL for Mimecast API 2.0. May also be set via MIMECAST_ADDRESS or MIMECAST_BASE_URL. Defaults to `https://api.services.mimecast.com`.",
				Optional:    true,
				Validators:  []validator.String{urlValidator{}},
			},
			"token_url": schema.StringAttribute{
				Description: "OAuth token endpoint. May also be set via MIMECAST_TOKEN_URL. When omitted, it is derived as `<base_url>/oauth/token`.",
				Optional:    true,
				Validators:  []validator.String{urlValidator{}},
			},
			"client_id": schema.StringAttribute{
				Description: "Mimecast API 2.0 client ID. May also be set via MIMECAST_CLIENT_ID.",
				Optional:    true,
			},
			"client_secret": schema.StringAttribute{
				Description: "Mimecast API 2.0 client secret. May also be set via MIMECAST_SECRET or MIMECAST_CLIENT_SECRET.",
				Optional:    true,
				Sensitive:   true,
			},
			"token_auth_method": schema.StringAttribute{
				Description: "OAuth client authentication method. Supported values: `client_secret_post`, `client_secret_basic`. May also be set via MIMECAST_TOKEN_AUTH_METHOD. Defaults to `client_secret_post`.",
				Optional:    true,
			},
			"scopes": schema.ListAttribute{
				Description: "Optional OAuth scopes to request.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"insecure": schema.BoolAttribute{
				Description: "Skip TLS certificate verification. May also be set via MIMECAST_INSECURE. Disabled by default.",
				Optional:    true,
			},
			"timeout_seconds": schema.Int64Attribute{
				Description: "HTTP request timeout in seconds. May also be set via MIMECAST_TIMEOUT_SECONDS. Defaults to 30.",
				Optional:    true,
				Validators:  []validator.Int64{positiveInt64Validator{}},
			},
			"max_retries": schema.Int64Attribute{
				Description: "Maximum retries for transient API failures and rate limits. May also be set via MIMECAST_MAX_RETRIES. Defaults to 4.",
				Optional:    true,
				Validators:  []validator.Int64{nonNegativeInt64Validator{}},
			},
			"page_size": schema.Int64Attribute{
				Description: "Page size for paginated list APIs. May also be set via MIMECAST_PAGE_SIZE. Defaults to 100.",
				Optional:    true,
				Validators:  []validator.Int64{positiveInt64Validator{}},
			},
			"read_only": schema.BoolAttribute{
				Description: "Fail closed before every create, update, or delete request. May also be set via MIMECAST_READ_ONLY. Defaults to true.",
				Optional:    true,
			},
			"proxy_url": schema.StringAttribute{
				Description: "Dedicated HTTP or HTTPS proxy for Mimecast API and OAuth requests. May also be set via MIMECAST_PROXY_URL. This is separate from Terraform backend proxy settings.",
				Optional:    true,
				Sensitive:   true,
				Validators:  []validator.String{urlValidator{}},
			},
		},
	}
}

func (p *MimecastProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	baseURL := firstNonEmpty(data.BaseURL.ValueString(), os.Getenv("MIMECAST_ADDRESS"), os.Getenv("MIMECAST_BASE_URL"), client.DefaultBaseURL)
	tokenURL := firstNonEmpty(data.TokenURL.ValueString(), os.Getenv("MIMECAST_TOKEN_URL"))
	clientID := firstNonEmpty(data.ClientID.ValueString(), os.Getenv("MIMECAST_CLIENT_ID"))
	clientSecret := firstNonEmpty(data.ClientSecret.ValueString(), os.Getenv("MIMECAST_SECRET"), os.Getenv("MIMECAST_CLIENT_SECRET"))
	authMethod := firstNonEmpty(data.TokenAuthMethod.ValueString(), os.Getenv("MIMECAST_TOKEN_AUTH_METHOD"), "client_secret_post")

	insecure := boolFrom(data.Insecure, "MIMECAST_INSECURE", false)
	timeout := int64From(data.TimeoutSeconds, "MIMECAST_TIMEOUT_SECONDS", 30)
	retries := int64From(data.MaxRetries, "MIMECAST_MAX_RETRIES", 4)
	pageSize := int64From(data.PageSize, "MIMECAST_PAGE_SIZE", 100)
	readOnly := boolFrom(data.ReadOnly, "MIMECAST_READ_ONLY", true)
	proxyURL := firstNonEmpty(data.ProxyURL.ValueString(), os.Getenv("MIMECAST_PROXY_URL"))

	var scopes []string
	if !data.Scopes.IsNull() && !data.Scopes.IsUnknown() {
		resp.Diagnostics.Append(data.Scopes.ElementsAs(ctx, &scopes, false)...)
	}
	if envScopes := strings.TrimSpace(os.Getenv("MIMECAST_SCOPES")); len(scopes) == 0 && envScopes != "" {
		scopes = strings.Fields(envScopes)
	}
	if clientID == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("client_id"), "Missing Mimecast client ID", "Set client_id or MIMECAST_CLIENT_ID.")
	}
	if clientSecret == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("client_secret"), "Missing Mimecast client secret", "Set client_secret or MIMECAST_CLIENT_SECRET.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := client.New(client.Config{
		BaseURL: baseURL, TokenURL: tokenURL, ClientID: clientID, ClientSecret: clientSecret, TokenAuthMethod: authMethod,
		Scopes: scopes, Insecure: insecure, UserAgent: "terraform-provider-mimecast/" + p.version,
		Timeout: time.Duration(timeout) * time.Second, MaxRetries: int(retries), PageSize: int(pageSize),
		ReadOnly: readOnly, ProxyURL: proxyURL,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Mimecast client", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *MimecastProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewGreylistingPolicyResource,
		NewDeliveryRoutePolicyResource,
		NewAntiSpoofingPolicyResource,
		NewAntiSpoofingBypassPolicyResource,
		NewBlockedSenderPolicyResource,
		NewDNSAuthenticationOutboundPolicyResource,
		NewDeliveryRouteDefinitionResource,
		NewDNSAuthenticationOutboundDefinitionResource,
		NewManagedURLResource,
		NewProfileGroupResource,
		NewProfileGroupMemberResource,
		NewOutboundIPAddressesResource,
		NewCloudIntegratedPolicyResource,
		NewDMARCManagedDomainResource,
		NewDMARCDomainGroupResource,
		NewDMARCNotificationResource,
		NewDMARCPolicyPresetResource,
		NewDMARCDelegatedDomainResource,
		NewDMARCDomainGroupAssociationResource,
		NewDMARCDefinitionResource,
		NewDMARCDKIMDefinitionResource,
		NewDMARCSPFDefinitionResource,
		NewDMARCUserResource,
		NewActiveDirectoryIntegrationResource,
		NewGoogleWorkspaceDirectoryIntegrationResource,
		NewMicrosoft365DirectoryIntegrationResource,
		NewAddressAlterationDefinitionResource,
		NewAddressAlterationPolicyResource,
		NewWebSecurityURLPolicyResource,
		NewThreatReportingSubscriptionResource,
		NewJournalingServiceResource,
	}
}

func (p *MimecastProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewWhoamiDataSource,
		NewGatewayDetailsDataSource,
		NewAccountDataSource,
		NewAccountPackagesDataSource,
		NewEmergencyContactDataSource,
		NewInternalDomainsDataSource,
		NewPendingDomainsDataSource,
		NewExternalDomainsDataSource,
		NewProfileGroupsDataSource,
		NewProfileGroupMembersDataSource,
		NewUsersDataSource,
		NewRolesDataSource,
		NewGreylistingPoliciesDataSource,
		NewDeliveryRoutePoliciesDataSource,
		NewAntiSpoofingPoliciesDataSource,
		NewAntiSpoofingBypassPoliciesDataSource,
		NewBlockedSenderPoliciesDataSource,
		NewDNSAuthenticationOutboundPoliciesDataSource,
		NewDeliveryRouteDefinitionsDataSource,
		NewDNSAuthenticationOutboundDefinitionsDataSource,
		NewManagedURLsDataSource,
		NewJournalingServicesDataSource,
		NewConnectorsDataSource,
		NewOutboundIPAddressesDataSource,
		NewCloudIntegratedDefaultPolicyDataSource,
		NewDMARCDomainsDataSource,
		NewDMARCDomainGroupsDataSource,
		NewDMARCNotificationsDataSource,
		NewDMARCDelegatedDomainsDataSource,
		NewDMARCPolicyPresetsDataSource,
		NewDMARCVendorsDataSource,
		NewDMARCUsersDataSource,
		NewAddressAlterationSetsDataSource,
		NewAddressAlterationDefinitionsDataSource,
		NewAddressAlterationPoliciesDataSource,
		NewThreatReportingSubscriptionsDataSource,
	}
}

func (p *MimecastProvider) Functions(context.Context) []func() function.Function { return nil }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func boolFrom(v types.Bool, env string, def bool) bool {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueBool()
	}
	if parsed, err := strconv.ParseBool(os.Getenv(env)); err == nil {
		return parsed
	}
	return def
}

func int64From(v types.Int64, env string, def int64) int64 {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueInt64()
	}
	if parsed, err := strconv.ParseInt(os.Getenv(env), 10, 64); err == nil {
		return parsed
	}
	return def
}
