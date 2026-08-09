package provider

import (
	"context"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type serviceURLValidator struct{}

func (serviceURLValidator) Description(context.Context) string {
	return "must be an absolute HTTPS URL; HTTP is allowed only on numeric loopback addresses for testing"
}
func (serviceURLValidator) MarkdownDescription(ctx context.Context) string {
	return serviceURLValidator{}.Description(ctx)
}
func (serviceURLValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return
	}
	if !client.IsAllowedServiceURL(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid service URL", "Service URL must use HTTPS; HTTP is allowed only on numeric loopback addresses for testing.")
	}
}

type urlValidator struct{}

func (urlValidator) Description(context.Context) string         { return "must be an absolute URL" }
func (urlValidator) MarkdownDescription(context.Context) string { return "must be an absolute URL" }
func (urlValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return
	}
	u, err := url.Parse(req.ConfigValue.ValueString())
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid URL", "URL must use HTTP or HTTPS and include a host.")
	}
}

type managedURLAccessTokenValidator struct{}

func (managedURLAccessTokenValidator) Description(context.Context) string {
	return "must not contain a query parameter whose decoded name is access_token"
}
func (managedURLAccessTokenValidator) MarkdownDescription(ctx context.Context) string {
	return managedURLAccessTokenValidator{}.Description(ctx)
}
func (managedURLAccessTokenValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if client.ManagedURLValueHasAccessTokenQuery(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path, managedURLAccessTokenSummary, managedURLAccessTokenDetail)
	}
}

type positiveInt64Validator struct{}

func (positiveInt64Validator) Description(context.Context) string { return "must be greater than zero" }
func (positiveInt64Validator) MarkdownDescription(context.Context) string {
	return "must be greater than zero"
}
func (positiveInt64Validator) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueInt64() <= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", "Value must be greater than zero.")
	}
}

type nonNegativeInt64Validator struct{}

func (nonNegativeInt64Validator) Description(context.Context) string {
	return "must be zero or greater"
}
func (nonNegativeInt64Validator) MarkdownDescription(context.Context) string {
	return "must be zero or greater"
}
func (nonNegativeInt64Validator) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueInt64() < 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", "Value must be zero or greater.")
	}
}
