package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

func configureClient(data any, resp *resource.ConfigureResponse) *client.Client {
	c, ok := data.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", data))
		return nil
	}
	return c
}

func idAttr(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
}

func requiredString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Required: true}
}

func requiredReplaceString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func optionalString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Optional: true}
}

func optionalReplaceString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Optional: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func optionalReplaceStringWithValidators(desc string, validators ...validator.String) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Optional: true, Validators: validators, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func computedString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
}

func optionalComputedString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
}

func optionalComputedReplaceString(desc string) schema.StringAttribute {
	return schema.StringAttribute{Description: desc, Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}}
}

func optionalBool(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{Description: desc, Optional: true}
}

func optionalReplaceBool(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{Description: desc, Optional: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}}
}

func optionalComputedBool(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{Description: desc, Optional: true, Computed: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}}
}

func optionalComputedReplaceBool(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{Description: desc, Optional: true, Computed: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace(), boolplanmodifier.UseStateForUnknown()}}
}

func optionalInt64(desc string) schema.Int64Attribute {
	return schema.Int64Attribute{Description: desc, Optional: true}
}

func optionalComputedInt64(desc string) schema.Int64Attribute {
	return schema.Int64Attribute{Description: desc, Optional: true, Computed: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()}}
}

func optionalComputedReplaceInt64(desc string) schema.Int64Attribute {
	return schema.Int64Attribute{Description: desc, Optional: true, Computed: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace(), int64planmodifier.UseStateForUnknown()}}
}

func optionalStringList(desc string) schema.ListAttribute {
	return schema.ListAttribute{Description: desc, Optional: true, ElementType: types.StringType}
}

func optionalComputedStringList(desc string) schema.ListAttribute {
	return schema.ListAttribute{Description: desc, Optional: true, Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()}}
}

func stringValue(v string) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

func boolValue(v *bool) types.Bool {
	if v == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*v)
}

func boolPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}

func int64Value(v int64) types.Int64 {
	if v == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(v)
}

func stringsFromList(ctx context.Context, l types.List) ([]string, diag.Diagnostics) {
	if l.IsNull() || l.IsUnknown() {
		return nil, nil
	}
	var out []string
	diags := l.ElementsAs(ctx, &out, false)
	return out, diags
}

func stringsFromSet(ctx context.Context, set types.Set) ([]string, diag.Diagnostics) {
	if set.IsNull() || set.IsUnknown() {
		return nil, nil
	}
	var out []string
	diags := set.ElementsAs(ctx, &out, false)
	return out, diags
}

func listFromStrings(ctx context.Context, vals []string) (types.List, diag.Diagnostics) {
	if vals == nil {
		return types.ListNull(types.StringType), nil
	}
	items := make([]attr.Value, 0, len(vals))
	for _, v := range vals {
		items = append(items, types.StringValue(v))
	}
	return types.ListValue(types.StringType, items)
}

func setFromStrings(ctx context.Context, vals []string) (types.Set, diag.Diagnostics) {
	if vals == nil {
		return types.SetNull(types.StringType), nil
	}
	items := make([]attr.Value, 0, len(vals))
	for _, v := range vals {
		items = append(items, types.StringValue(v))
	}
	return types.SetValue(types.StringType, items)
}

func importIDPassthrough(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, pathRoot("id"), req, resp)
}

func normalizeCompositeID(parts ...string) string {
	return strings.Join(parts, "/")
}
