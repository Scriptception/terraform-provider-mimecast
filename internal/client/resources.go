package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type PolicyEndpoint struct {
	ListPath   string
	ObjectPath string
	ListKey    string
}

var PolicyEndpoints = map[string]PolicyEndpoint{
	"greylisting":                 {"/policy-management/cloud-gateway/v1/greylisting/policies", "/policy-management/cloud-gateway/v1/greylisting/policies/%s", "policies"},
	"delivery_route":              {"/policy-management/cloud-gateway/v1/delivery-route/policies", "/policy-management/cloud-gateway/v1/delivery-route/policies/%s", "policies"},
	"anti_spoofing":               {"/policy-management/cloud-gateway/v1/anti-spoofing/policies", "/policy-management/cloud-gateway/v1/anti-spoofing/policies/%s", "definitions"},
	"anti_spoofing_bypass":        {"/policy-management/cloud-gateway/v1/anti-spoofing-bypass/policies", "/policy-management/cloud-gateway/v1/anti-spoofing-bypass/policies/%s", "definitions"},
	"blocked_sender":              {"/policy-management/cloud-gateway/v1/blocked-senders/policies", "/policy-management/cloud-gateway/v1/blocked-senders/policies/%s", "definitions"},
	"dns_authentication_outbound": {"/policy-management/cloud-gateway/v1/dns-authentication-outbound/policies", "/policy-management/cloud-gateway/v1/dns-authentication-outbound/policies/%s", "policies"},
}

func (c *Client) CreatePolicy(ctx context.Context, kind string, p Policy) (string, error) {
	ep, ok := PolicyEndpoints[kind]
	if !ok {
		return "", fmt.Errorf("unknown policy kind %q", kind)
	}
	if kind == "greylisting" {
		p.FromDate, p.ToDate = p.FromDateTime, p.ToDateTime
		p.FromDateTime, p.ToDateTime = "", ""
	}
	var out IDResponsePolicy
	if err := c.Do(ctx, http.MethodPost, ep.ListPath, nil, p, &out); err != nil {
		return "", err
	}
	if out.PolicyID != "" {
		return out.PolicyID, nil
	}
	if out.ID == "" {
		return "", fmt.Errorf("mimecast: create %s policy response did not include an ID", kind)
	}
	return out.ID, nil
}

func (c *Client) GetPolicy(ctx context.Context, kind, id string) (Policy, error) {
	ep, ok := PolicyEndpoints[kind]
	if !ok {
		return Policy{}, fmt.Errorf("unknown policy kind %q", kind)
	}
	var out Policy
	err := c.Do(ctx, http.MethodGet, fmt.Sprintf(ep.ObjectPath, url.PathEscape(id)), nil, nil, &out)
	out.ID = id
	return out, err
}

func (c *Client) UpdatePolicy(ctx context.Context, kind, id string, p Policy) error {
	ep, ok := PolicyEndpoints[kind]
	if !ok {
		return fmt.Errorf("unknown policy kind %q", kind)
	}
	if kind == "greylisting" {
		p.FromDate, p.ToDate = p.FromDateTime, p.ToDateTime
		p.FromDateTime, p.ToDateTime = "", ""
	}
	return c.Do(ctx, http.MethodPatch, fmt.Sprintf(ep.ObjectPath, url.PathEscape(id)), nil, p, nil)
}

func (c *Client) DeletePolicy(ctx context.Context, kind, id string) error {
	ep, ok := PolicyEndpoints[kind]
	if !ok {
		return fmt.Errorf("unknown policy kind %q", kind)
	}
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf(ep.ObjectPath, url.PathEscape(id)), nil, nil, nil)
}

func (c *Client) ListPolicies(ctx context.Context, kind string) ([]Policy, error) {
	ep, ok := PolicyEndpoints[kind]
	if !ok {
		return nil, fmt.Errorf("unknown policy kind %q", kind)
	}
	items := make([]Policy, 0)
	type policyPage struct {
		Policies    []Policy `json:"policies"`
		Definitions []Policy `json:"definitions"`
		Meta        PageMeta `json:"meta"`
	}
	err := c.DoAllPages(ctx, ep.ListPath, nil, func() any { return &policyPage{} }, func(value any) error {
		page := value.(*policyPage)
		if ep.ListKey == "definitions" {
			if len(page.Definitions) > 0 {
				items = append(items, page.Definitions...)
			} else {
				items = append(items, page.Policies...)
			}
		} else {
			if len(page.Policies) > 0 {
				items = append(items, page.Policies...)
			} else {
				items = append(items, page.Definitions...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Description < items[j].Description
	})
	return items, nil
}

func (c *Client) CreateDeliveryRouteDefinition(ctx context.Context, d DeliveryRouteDefinition) (string, error) {
	var out IDResponse
	err := c.Do(ctx, http.MethodPost, "/policy-management/cloud-gateway/v1/delivery-route/definitions", nil, d, &out)
	if err == nil && out.ID == "" {
		err = fmt.Errorf("mimecast: create delivery route definition response did not include an ID")
	}
	return out.ID, err
}
func (c *Client) GetDeliveryRouteDefinition(ctx context.Context, id string) (DeliveryRouteDefinition, error) {
	var out DeliveryRouteDefinition
	err := c.Do(ctx, http.MethodGet, "/policy-management/cloud-gateway/v1/delivery-route/definitions/"+url.PathEscape(id), nil, nil, &out)
	out.ID = id
	return out, err
}
func (c *Client) UpdateDeliveryRouteDefinition(ctx context.Context, id string, d DeliveryRouteDefinition) error {
	return c.Do(ctx, http.MethodPatch, "/policy-management/cloud-gateway/v1/delivery-route/definitions/"+url.PathEscape(id), nil, d, nil)
}
func (c *Client) DeleteDeliveryRouteDefinition(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/policy-management/cloud-gateway/v1/delivery-route/definitions/"+url.PathEscape(id), nil, nil, nil)
}
func (c *Client) ListDeliveryRouteDefinitions(ctx context.Context) ([]DeliveryRouteDefinition, error) {
	type page struct {
		Definitions []DeliveryRouteDefinition `json:"definitions"`
		Meta        PageMeta                  `json:"meta"`
	}
	items := make([]DeliveryRouteDefinition, 0)
	err := c.DoAllPages(ctx, "/policy-management/cloud-gateway/v1/delivery-route/definitions", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Definitions...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func (c *Client) CreateDNSOutboundDefinition(ctx context.Context, d DNSOutboundDefinition) (string, error) {
	var out IDResponse
	err := c.Do(ctx, http.MethodPost, "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions", nil, d, &out)
	if err == nil && out.ID == "" {
		err = fmt.Errorf("mimecast: create DNS authentication outbound definition response did not include an ID")
	}
	return out.ID, err
}
func (c *Client) GetDNSOutboundDefinition(ctx context.Context, id string) (DNSOutboundDefinition, error) {
	var out DNSOutboundDefinition
	err := c.Do(ctx, http.MethodGet, "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions/"+url.PathEscape(id), nil, nil, &out)
	out.ID = id
	return out, err
}
func (c *Client) UpdateDNSOutboundDefinition(ctx context.Context, id string, d DNSOutboundDefinition) error {
	patch := DNSOutboundDefinition{Description: d.Description, SignDKIM: d.SignDKIM}
	return c.Do(ctx, http.MethodPatch, "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions/"+url.PathEscape(id), nil, patch, nil)
}
func (c *Client) DeleteDNSOutboundDefinition(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions/"+url.PathEscape(id), nil, nil, nil)
}
func (c *Client) ListDNSOutboundDefinitions(ctx context.Context) ([]DNSOutboundDefinition, error) {
	type page struct {
		Definitions            []DNSOutboundDefinition `json:"definitions"`
		DNSOutboundDefinitions []DNSOutboundDefinition `json:"dnsOutboundDefinitions"`
		Meta                   PageMeta                `json:"meta"`
	}
	items := make([]DNSOutboundDefinition, 0)
	err := c.DoAllPages(ctx, "/policy-management/cloud-gateway/v1/dns-authentication-outbound/definitions", nil, func() any { return &page{} }, func(value any) error {
		p := value.(*page)
		if len(p.DNSOutboundDefinitions) > 0 {
			items = append(items, p.DNSOutboundDefinitions...)
		} else {
			items = append(items, p.Definitions...)
		}
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func (c *Client) CreateManagedURL(ctx context.Context, m ManagedURL) (string, error) {
	type createRequest struct {
		URL                  string `json:"url,omitempty"`
		Action               string `json:"action,omitempty"`
		MatchType            string `json:"matchType,omitempty"`
		Comment              string `json:"comment,omitempty"`
		DisableLogClick      *bool  `json:"disableLogClick,omitempty"`
		DisableRewrite       *bool  `json:"disableRewrite,omitempty"`
		DisableUserAwareness *bool  `json:"disableUserAwareness,omitempty"`
	}
	request := createRequest{
		URL:                  m.URL,
		Action:               m.Action,
		MatchType:            m.MatchType,
		Comment:              m.Comment,
		DisableLogClick:      m.DisableLogClick,
		DisableRewrite:       m.DisableRewrite,
		DisableUserAwareness: m.DisableUserAwareness,
	}
	var out LegacyEnvelope[ManagedURL]
	err := c.Do(ctx, http.MethodPost, "/api/ttp/url/create-managed-url", nil, map[string]any{"data": []createRequest{request}}, &out)
	if err != nil {
		return "", err
	}
	c.invalidateManagedURLInventory()
	if len(out.Data) == 0 {
		return "", nil
	}
	return out.Data[0].ID, nil
}

func (c *Client) DeleteManagedURL(ctx context.Context, id string) error {
	err := c.Do(ctx, http.MethodPost, "/api/ttp/url/delete-managed-url", nil, map[string]any{"data": []ManagedURL{{ID: id}}}, nil)
	if err != nil && !IsNotFound(err) {
		return err
	}
	c.invalidateManagedURLInventory()
	return err
}

func (c *Client) ListManagedURLs(ctx context.Context, filter string, exact bool) ([]ManagedURL, error) {
	if filter != "" {
		return c.listManagedURLs(ctx, filter, exact)
	}

	// A Terraform command shares one provider client across concurrent resource
	// refreshes. Keep one process-scoped unfiltered snapshot so hundreds of
	// resources neither stampede nor repeatedly download the full inventory.
	// Successful mutations invalidate the snapshot. Holding this dedicated lock
	// across the initial fetch also makes the snapshot a single-flight operation.
	c.managedURLInventoryMu.Lock()
	defer c.managedURLInventoryMu.Unlock()
	if c.managedURLInventoryValid {
		return cloneManagedURLs(c.managedURLInventory), nil
	}
	items, err := c.listManagedURLs(ctx, "", false)
	if err != nil {
		return nil, err
	}
	c.managedURLInventory = cloneManagedURLs(items)
	c.managedURLInventoryValid = true
	return cloneManagedURLs(c.managedURLInventory), nil
}

func (c *Client) listManagedURLs(ctx context.Context, filter string, exact bool) ([]ManagedURL, error) {
	req := map[string]any{}
	if filter != "" {
		req["domainOrUrl"] = filter
		req["exactMatch"] = exact
	}
	items := make([]ManagedURL, 0)
	pageToken := ""
	seen := map[string]struct{}{}
	for {
		pagination := map[string]any{"pageSize": c.pageSize}
		if pageToken != "" {
			pagination["pageToken"] = pageToken
		}
		body := map[string]any{
			"meta": map[string]any{"pagination": pagination},
		}
		if filter != "" {
			body["data"] = []any{req}
		}
		var out LegacyEnvelope[ManagedURL]
		if err := c.DoRead(ctx, http.MethodPost, "/api/ttp/url/get-all-managed-urls", nil, body, &out); err != nil {
			return nil, err
		}
		for i := range out.Data {
			canonicalizeManagedURL(&out.Data[i])
			items = append(items, out.Data[i])
		}
		next := out.Meta.Pagination.Next
		if next == "" {
			break
		}
		if _, ok := seen[next]; ok {
			return nil, fmt.Errorf("mimecast: managed URL pagination repeated a page token")
		}
		seen[next] = struct{}{}
		pageToken = next
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].URL < items[j].URL
	})
	return items, nil
}

func (c *Client) invalidateManagedURLInventory() {
	c.managedURLInventoryMu.Lock()
	defer c.managedURLInventoryMu.Unlock()
	c.managedURLInventory = nil
	c.managedURLInventoryValid = false
}

func cloneManagedURLs(items []ManagedURL) []ManagedURL {
	if items == nil {
		return nil
	}
	cloned := make([]ManagedURL, len(items))
	for i := range items {
		cloned[i] = items[i]
		cloned[i].DisableLogClick = cloneBool(items[i].DisableLogClick)
		cloned[i].DisableRewrite = cloneBool(items[i].DisableRewrite)
		cloned[i].DisableUserAwareness = cloneBool(items[i].DisableUserAwareness)
	}
	return cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// ManagedURLValueHasAccessTokenQuery reports whether a URL contains a query
// parameter whose decoded name is exactly access_token. Query extraction is
// deliberately independent of URL parsing so malformed URLs cannot bypass the
// state-safety boundary. Parameter values are never decoded or inspected.
func ManagedURLValueHasAccessTokenQuery(value string) bool {
	queryStart := strings.IndexByte(value, '?')
	if queryStart < 0 {
		return false
	}
	fragmentStart := strings.IndexByte(value, '#')
	if fragmentStart >= 0 && fragmentStart < queryStart {
		return false
	}
	queryEnd := len(value)
	if fragmentStart > queryStart {
		queryEnd = fragmentStart
	}
	return managedURLQueryHasAccessTokenName(value[queryStart+1 : queryEnd])
}

// ManagedURLHasAccessTokenQuery checks the composite URL and every documented
// decomposed URL component. Components are checked independently so ignored or
// irreconstructible response shapes cannot retain a credential value.
func ManagedURLHasAccessTokenQuery(item ManagedURL) bool {
	return item.hasAccessTokenQuery ||
		ManagedURLValueHasAccessTokenQuery(item.URL) ||
		ManagedURLValueHasAccessTokenQuery(item.Scheme) ||
		ManagedURLValueHasAccessTokenQuery(item.Domain) ||
		ManagedURLValueHasAccessTokenQuery(item.Path) ||
		managedURLQueryHasAccessTokenName(item.QueryString)
}

func managedURLQueryHasAccessTokenName(query string) bool {
	query = strings.TrimPrefix(query, "?")
	for _, parameter := range strings.Split(query, "&") {
		name, _, _ := strings.Cut(parameter, "=")
		decodedName, err := url.QueryUnescape(name)
		if err == nil && strings.EqualFold(decodedName, "access_token") {
			return true
		}
	}
	return false
}

func canonicalizeManagedURL(item *ManagedURL) {
	if sanitizeManagedURL(item) {
		return
	}
	item.Action = strings.ToLower(strings.TrimSpace(item.Action))
	item.MatchType = strings.ToLower(strings.TrimSpace(item.MatchType))
	if item.URL != "" {
		return
	}

	domain := strings.TrimSpace(item.Domain)
	switch item.MatchType {
	case "domain":
		if domain == "" {
			return
		}
		item.URL = domain
	case "explicit":
		scheme := strings.TrimSpace(item.Scheme)
		if scheme == "" || domain == "" || item.Port < -1 || item.Port > 65535 {
			return
		}
		var value strings.Builder
		value.WriteString(scheme)
		value.WriteString("://")
		value.WriteString(domain)
		if item.Port > 0 {
			value.WriteByte(':')
			value.WriteString(strconv.FormatInt(item.Port, 10))
		}
		if item.Path != "" {
			if !strings.HasPrefix(item.Path, "/") {
				value.WriteByte('/')
			}
			value.WriteString(item.Path)
		}
		if item.QueryString != "" {
			value.WriteByte('?')
			value.WriteString(strings.TrimPrefix(item.QueryString, "?"))
		}
		item.URL = value.String()
	}
	sanitizeManagedURL(item)
}

func sanitizeManagedURL(item *ManagedURL) bool {
	if !ManagedURLHasAccessTokenQuery(*item) {
		return false
	}
	id := item.ID
	*item = ManagedURL{ID: id, hasAccessTokenQuery: true}
	return true
}
