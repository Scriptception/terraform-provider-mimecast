package provider

import (
	"context"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type urlValidator struct{}

func (urlValidator) Description(context.Context) string         { return "must be an absolute URL" }
func (urlValidator) MarkdownDescription(context.Context) string { return "must be an absolute URL" }
func (urlValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return
	}
	u, err := url.Parse(req.ConfigValue.ValueString())
	if err != nil || u.Scheme == "" || u.Host == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid URL", "URL must include a scheme and host.")
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
