package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-mimecast/internal/client"
)

type attributeTypeItemModel struct {
	ID             types.String `tfsdk:"id"`
	Description    types.String `tfsdk:"description"`
	Prompt         types.String `tfsdk:"prompt"`
	PromptGroup    types.String `tfsdk:"prompt_group"`
	PromptType     types.Int64  `tfsdk:"prompt_type"`
	PromptOrder    types.Int64  `tfsdk:"prompt_order"`
	PromptOptions  types.String `tfsdk:"prompt_options"`
	AllowedInViews types.Bool   `tfsdk:"allowed_in_views"`
}
type attributeTypesModel struct {
	ID    types.String             `tfsdk:"id"`
	Items []attributeTypeItemModel `tfsdk:"items"`
}

func NewAttributeTypesDataSource() datasource.DataSource {
	attrs := map[string]dsschema.Attribute{
		"id": dsID("Stable attribute type inventory ID."),
		"items": dsItems(map[string]dsschema.Attribute{
			"id": dsID("Attribute type UUID."), "description": dsString("Attribute type description."),
			"prompt": dsString("Display label."), "prompt_group": dsString("Display group."),
			"prompt_type":      dsInt64("Input control type, including 50 for LDAP-linked attributes."),
			"prompt_order":     dsInt64("Display order within the group."),
			"prompt_options":   dsString("Unmodified comma-delimited selection options from the API."),
			"allowed_in_views": dsBool("Whether the type may be displayed in table views."),
		}),
	}
	return newTypedDataSource("attribute_types", "Read all local and directory-linked attribute definitions with cursor pagination, sorted by ID. Requires Directories | Attributes | Read. Does not read address attribute values or modify directory configuration.", attrs, func(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse, c *client.Client) {
		out, err := c.ListAttributeTypes(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read attribute types", err.Error())
			return
		}
		items := make([]attributeTypeItemModel, 0, len(out))
		for _, item := range out {
			items = append(items, attributeTypeItemModel{
				ID: types.StringValue(item.ID), Description: types.StringValue(item.Description),
				Prompt: types.StringValue(item.Prompt), PromptGroup: types.StringValue(item.PromptGroup),
				PromptType: types.Int64PointerValue(item.PromptType), PromptOrder: types.Int64PointerValue(item.PromptOrder),
				PromptOptions: types.StringValue(item.PromptOptions), AllowedInViews: types.BoolPointerValue(item.AllowedInViews),
			})
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &attributeTypesModel{ID: types.StringValue("attribute_types"), Items: items})...)
	})
}
