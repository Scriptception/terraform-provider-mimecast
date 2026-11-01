package client

import (
	"context"
	"fmt"
	"sort"
)

// AttributeType is directory metadata, not an address's attribute values.
// Contract: the public directory product GET /directory/v1/attributeTypes.
type AttributeType struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	Prompt         string `json:"prompt"`
	PromptGroup    string `json:"promptGroup"`
	PromptType     *int64 `json:"promptType"`
	PromptOrder    *int64 `json:"promptOrder"`
	PromptOptions  string `json:"promptOptions"`
	AllowedInViews *bool  `json:"allowedInViews"`
}

func (c *Client) ListAttributeTypes(ctx context.Context) ([]AttributeType, error) {
	type page struct {
		AttributeTypes []AttributeType `json:"attributeTypes"`
		Meta           PageMeta        `json:"meta"`
	}
	// The provider-wide page size is capped at 100, below this endpoint
	// maximum of 1000. Omit origin to include local and directory types;
	// omit includeCount because it cannot be combined with pageToken.
	items := make([]AttributeType, 0)
	seen := make(map[string]bool)
	err := c.DoAllPages(ctx, "/directory/v1/attributeTypes", nil, func() any { return &page{} }, func(value any) error {
		entries := value.(*page).AttributeTypes
		if entries == nil {
			return fmt.Errorf("mimecast: attribute type inventory is missing or null")
		}
		for _, item := range entries {
			if item.ID == "" || seen[item.ID] {
				return fmt.Errorf("mimecast: attribute type inventory has missing or duplicate IDs")
			}
			seen[item.ID] = true
			items = append(items, item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}
