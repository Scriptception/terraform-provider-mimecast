package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

type AccountCodes struct {
	CI   string `json:"ci,omitempty"`
	CG   string `json:"cg,omitempty"`
	X1   string `json:"x1,omitempty"`
	Lead string `json:"lead,omitempty"`
}

type WhoAmI struct {
	Version      string       `json:"version,omitempty"`
	Type         string       `json:"type,omitempty"`
	AccountCodes AccountCodes `json:"account-codes,omitempty"`
	HomeAccount  AccountCodes `json:"home-account,omitempty"`
}

type GatewayDetails struct {
	AccountCode    string `json:"accountCode,omitempty"`
	Region         string `json:"region,omitempty"`
	ProtectionMode string `json:"protectionMode,omitempty"`
	Status         string `json:"status,omitempty"`
}

type EmergencyContact struct {
	AccountCode             string   `json:"accountCode,omitempty"`
	ContactName             string   `json:"contactName,omitempty"`
	ContactEmailAddress     string   `json:"contactEmailAddress,omitempty"`
	MobilePhone             string   `json:"mobilePhone,omitempty"`
	Telephone               string   `json:"telephone,omitempty"`
	AlternateEmailAddresses []string `json:"alternateEmailAddresses,omitempty"`
}

type AccountPackageName string

func (p *AccountPackageName) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		*p = AccountPackageName(value)
		return nil
	}
	var object struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("mimecast: decode account package")
	}
	for _, candidate := range []string{object.Name, object.Code, object.ID} {
		if candidate != "" {
			*p = AccountPackageName(candidate)
			return nil
		}
	}
	return nil
}

type AccountSummary struct {
	AccountCode           string               `json:"accountCode,omitempty"`
	AccountName           string               `json:"accountName,omitempty"`
	MimecastID            string               `json:"mimecastId,omitempty"`
	Region                string               `json:"region,omitempty"`
	Type                  string               `json:"type,omitempty"`
	MailPlatform          string               `json:"mailPlatform,omitempty"`
	Gateway               *bool                `json:"gateway,omitempty"`
	Archive               *bool                `json:"archive,omitempty"`
	PolicyInheritance     *bool                `json:"policyInheritance,omitempty"`
	MaxRetention          int64                `json:"maxRetention,omitempty"`
	MinRetentionEnabled   *bool                `json:"minRetentionEnabled,omitempty"`
	UserCount             int64                `json:"userCount,omitempty"`
	Packages              []AccountPackageName `json:"packages,omitempty"`
	CybergraphV2Enabled   *bool                `json:"cybergraphV2Enabled,omitempty"`
	ExportAPI             *bool                `json:"exportApi,omitempty"`
	AutomatedSegmentPurge *bool                `json:"automatedSegmentPurge,omitempty"`
}

type ProvisionedProduct struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ProvisionedPackage struct {
	Products ProvisionedProduct `json:"products,omitempty"`
}

type Domain struct {
	ID          string `json:"id,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Local       *bool  `json:"local,omitempty"`
	SendOnly    *bool  `json:"sendOnly,omitempty"`
	InboundType string `json:"inboundType,omitempty"`
}

type DirectoryUser struct {
	ID              string `json:"id,omitempty"`
	EmailAddress    string `json:"emailAddress,omitempty"`
	Name            string `json:"name,omitempty"`
	Domain          string `json:"domain,omitempty"`
	Type            string `json:"type,omitempty"`
	Internal        *bool  `json:"internal,omitempty"`
	Disabled        *bool  `json:"disabled,omitempty"`
	CreatedDateTime string `json:"createdDateTime,omitempty"`
	UpdatedDateTime string `json:"updatedDateTime,omitempty"`
}

type Role struct {
	ID       string `json:"id,omitempty"`
	RoleName string `json:"roleName,omitempty"`
}

func (c *Client) GetWhoAmI(ctx context.Context) (WhoAmI, error) {
	var out WhoAmI
	err := c.Do(ctx, http.MethodGet, "/identity/whoami", nil, nil, &out)
	return out, err
}

func (c *Client) GetGatewayDetails(ctx context.Context) (GatewayDetails, error) {
	var out GatewayDetails
	err := c.Do(ctx, http.MethodGet, "/email/cloud-gateway/v1/gateway-details", nil, nil, &out)
	return out, err
}

func (c *Client) GetEmergencyContact(ctx context.Context) (EmergencyContact, error) {
	var out EmergencyContact
	err := c.Do(ctx, http.MethodGet, "/account/cloud-gateway/v1/emergency-contact", nil, nil, &out)
	sort.Strings(out.AlternateEmailAddresses)
	return out, err
}

func (c *Client) GetAccountSummary(ctx context.Context) (AccountSummary, error) {
	var out LegacyEnvelope[AccountSummary]
	err := c.DoRead(ctx, http.MethodPost, "/api/account/get-account", nil, map[string]any{"data": []any{map[string]any{}}}, &out)
	if err != nil {
		return AccountSummary{}, err
	}
	if len(out.Data) != 1 {
		return AccountSummary{}, fmt.Errorf("mimecast: account summary returned %d records, expected one", len(out.Data))
	}
	sort.Slice(out.Data[0].Packages, func(i, j int) bool { return out.Data[0].Packages[i] < out.Data[0].Packages[j] })
	return out.Data[0], nil
}

func (c *Client) ListProvisionedPackages(ctx context.Context) ([]ProvisionedPackage, error) {
	var out LegacyEnvelope[ProvisionedPackage]
	err := c.DoRead(ctx, http.MethodPost, "/api/provisioning/get-packages", nil, map[string]any{"data": []any{map[string]any{}}}, &out)
	sort.SliceStable(out.Data, func(i, j int) bool {
		if out.Data[i].Products.ID != out.Data[j].Products.ID {
			return out.Data[i].Products.ID < out.Data[j].Products.ID
		}
		return out.Data[i].Products.Name < out.Data[j].Products.Name
	})
	return out.Data, err
}

func (c *Client) ListInternalDomains(ctx context.Context) ([]Domain, error) {
	return c.listDomains(ctx, "/domain/cloud-gateway/v1/internal-domains")
}

func (c *Client) ListExternalDomains(ctx context.Context) ([]Domain, error) {
	return c.listDomains(ctx, "/domain/cloud-gateway/v1/external-domains")
}

func (c *Client) listDomains(ctx context.Context, path string) ([]Domain, error) {
	type page struct {
		Domains []Domain `json:"domains"`
		Meta    PageMeta `json:"meta"`
	}
	items := make([]Domain, 0)
	err := c.DoAllPages(ctx, path, nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Domains...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Domain < items[j].Domain
	})
	return items, err
}

func (c *Client) ListUsers(ctx context.Context) ([]DirectoryUser, error) {
	type page struct {
		Users []DirectoryUser `json:"users"`
		Meta  PageMeta        `json:"meta"`
	}
	items := make([]DirectoryUser, 0)
	err := c.DoAllPages(ctx, "/user/cloud-gateway/v1/users", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Users...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].EmailAddress < items[j].EmailAddress
	})
	return items, err
}

func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	type page struct {
		Roles []Role   `json:"roles"`
		Meta  PageMeta `json:"meta"`
	}
	items := make([]Role, 0)
	err := c.DoAllPages(ctx, "/role/cloud-gateway/v1/roles", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Roles...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

// DMARCDomainReference is the shared typed reference returned by current
// DMARC Analyzer group and notification contracts. Some responses use a bare
// ID string while others return the full object.
type DMARCDomainReference struct {
	ID     string `json:"id,omitempty"`
	Domain string `json:"domain,omitempty"`
	Name   string `json:"name,omitempty"`
}

func (r *DMARCDomainReference) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		r.ID = value
		return nil
	}
	type alias DMARCDomainReference
	var object alias
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("mimecast: decode DMARC reference")
	}
	*r = DMARCDomainReference(object)
	return nil
}

// CanonicalJSON is used only for semantic equality of provider-managed nested
// objects. It never includes HTTP response bodies in errors.
func CanonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("mimecast: encode canonical object: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, fmt.Errorf("mimecast: compact canonical object: %w", err)
	}
	return compact.Bytes(), nil
}
