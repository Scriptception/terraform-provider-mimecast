package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const dmarcAnalyzerV1Path = "/dmarc-analyzer/v1"

// DMARCDNSRecordValue is the typed value returned for a managed domain DNS record.
type DMARCDNSRecordValue struct {
	Domain   string `json:"domain,omitempty"`
	Value    string `json:"value,omitempty"`
	Selector string `json:"selector,omitempty"`
}

// DMARCDNSRecords contains all DNS record families returned for a managed domain.
type DMARCDNSRecords struct {
	A      []DMARCDNSRecordValue `json:"a,omitempty"`
	AAAA   []DMARCDNSRecordValue `json:"aaaa,omitempty"`
	CNAME  []DMARCDNSRecordValue `json:"cname,omitempty"`
	MX     []DMARCDNSRecordValue `json:"mx,omitempty"`
	NS     []DMARCDNSRecordValue `json:"ns,omitempty"`
	TXT    []DMARCDNSRecordValue `json:"txt,omitempty"`
	PTR    []DMARCDNSRecordValue `json:"ptr,omitempty"`
	SRV    []DMARCDNSRecordValue `json:"srv,omitempty"`
	SOA    []DMARCDNSRecordValue `json:"soa,omitempty"`
	CAA    []DMARCDNSRecordValue `json:"caa,omitempty"`
	DS     []DMARCDNSRecordValue `json:"ds,omitempty"`
	DNSKEY []DMARCDNSRecordValue `json:"dnskey,omitempty"`
	DMARC  []DMARCDNSRecordValue `json:"dmarc,omitempty"`
	DKIM   []DMARCDNSRecordValue `json:"dkim,omitempty"`
}

// ManagedDMARCDomain is the complete managed-domain representation returned by API v1.
type ManagedDMARCDomain struct {
	ID                string           `json:"id,omitempty"`
	Domain            string           `json:"domain,omitempty"`
	ActivityStatus    string           `json:"activityStatus,omitempty"`
	DetectedStatus    string           `json:"detectedStatus,omitempty"`
	Status            string           `json:"status,omitempty"`
	DMARCPolicy       string           `json:"dmarcPolicy,omitempty"`
	DMARCStatus       string           `json:"dmarcStatus,omitempty"`
	DMARCDelegationID string           `json:"dmarcDelegationId,omitempty"`
	DKIMStatus        string           `json:"dkimStatus,omitempty"`
	DKIMDelegationID  string           `json:"dkimDelegationId,omitempty"`
	SPFStatus         string           `json:"spfStatus,omitempty"`
	SPFDelegationID   string           `json:"spfDelegationId,omitempty"`
	IsPolicyInherited *bool            `json:"isPolicyInherited,omitempty"`
	DNSRecords        *DMARCDNSRecords `json:"dnsRecords,omitempty"`
}

type createManagedDMARCDomainResponse struct {
	Items []struct {
		Domain string `json:"domain"`
		ID     string `json:"id"`
	} `json:"items"`
}

// CreateManagedDMARCDomain creates one Terraform-addressable managed domain.
func (c *Client) CreateManagedDMARCDomain(ctx context.Context, domain string) (string, error) {
	request := struct {
		Items []string `json:"items"`
	}{Items: []string{domain}}
	var response createManagedDMARCDomainResponse
	if err := c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/domains", nil, request, &response); err != nil {
		return "", err
	}
	for _, item := range response.Items {
		if strings.EqualFold(item.Domain, domain) && item.ID != "" {
			return item.ID, nil
		}
	}
	return "", fmt.Errorf("mimecast: create managed DMARC domain returned no ID for requested domain")
}

// GetManagedDMARCDomain retrieves one managed domain by ID.
func (c *Client) GetManagedDMARCDomain(ctx context.Context, id string) (ManagedDMARCDomain, error) {
	var response ManagedDMARCDomain
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/domains/"+url.PathEscape(id), nil, nil, &response)
	normalizeManagedDMARCDomain(&response)
	return response, err
}

// ListManagedDMARCDomains retrieves every managed domain using cursor pagination.
func (c *Client) ListManagedDMARCDomains(ctx context.Context) ([]ManagedDMARCDomain, error) {
	type page struct {
		Items []ManagedDMARCDomain `json:"items"`
		Meta  PageMeta             `json:"meta"`
	}
	items := make([]ManagedDMARCDomain, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/domains", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	for index := range items {
		normalizeManagedDMARCDomain(&items[index])
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

// UpdateManagedDMARCDomain changes the only mutable domain field exposed by the API.
func (c *Client) UpdateManagedDMARCDomain(ctx context.Context, id, activityStatus string) error {
	request := struct {
		ActivityStatus string `json:"activityStatus"`
	}{ActivityStatus: activityStatus}
	return c.Do(ctx, http.MethodPatch, dmarcAnalyzerV1Path+"/domains/"+url.PathEscape(id), nil, request, nil)
}

// DeleteManagedDMARCDomain deletes one managed domain.
func (c *Client) DeleteManagedDMARCDomain(ctx context.Context, id string) error {
	query := url.Values{}
	query.Set("id", id)
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/domains", query, nil, nil)
}

func normalizeManagedDMARCDomain(domain *ManagedDMARCDomain) {
	if domain == nil || domain.DNSRecords == nil {
		return
	}
	for _, records := range [][]DMARCDNSRecordValue{
		domain.DNSRecords.A, domain.DNSRecords.AAAA, domain.DNSRecords.CNAME, domain.DNSRecords.MX,
		domain.DNSRecords.NS, domain.DNSRecords.TXT, domain.DNSRecords.PTR, domain.DNSRecords.SRV,
		domain.DNSRecords.SOA, domain.DNSRecords.CAA, domain.DNSRecords.DS, domain.DNSRecords.DNSKEY,
		domain.DNSRecords.DMARC, domain.DNSRecords.DKIM,
	} {
		sort.SliceStable(records, func(i, j int) bool {
			left := records[i].Domain + "\x00" + records[i].Selector + "\x00" + records[i].Value
			right := records[j].Domain + "\x00" + records[j].Selector + "\x00" + records[j].Value
			return left < right
		})
	}
}

// DMARCDomainGroupRequest models the official create and update request.
type DMARCDomainGroupRequest struct {
	Name                         string    `json:"name"`
	Type                         string    `json:"type"`
	DoesAutoIncludeOrgSubdomains *bool     `json:"doesAutoIncludeOrgSubdomains,omitempty"`
	IncludeDomainsWithStatus     string    `json:"includeDomainsWithStatus,omitempty"`
	IncludedDomains              *[]string `json:"includedDomains,omitempty"`
	IncludeDomainsRegex          *[]string `json:"includeDomainsRegex,omitempty"`
}

// ManagedDMARCDomainGroup is the typed domain-group response.
type ManagedDMARCDomainGroup struct {
	ID                           string                 `json:"id,omitempty"`
	Name                         string                 `json:"name,omitempty"`
	Type                         string                 `json:"type,omitempty"`
	DoesAutoIncludeOrgSubdomains *bool                  `json:"doesAutoIncludeOrgSubdomains,omitempty"`
	IncludeDomainsWithStatus     string                 `json:"includeDomainsWithStatus,omitempty"`
	IncludedDomains              []DMARCDomainReference `json:"includedDomains,omitempty"`
	IncludeDomainsRegex          []string               `json:"includeDomainsRegex,omitempty"`
	DomainsCount                 int64                  `json:"domainsCount,omitempty"`
}

// CreateManagedDMARCDomainGroup creates a domain group and returns its ID.
func (c *Client) CreateManagedDMARCDomainGroup(ctx context.Context, request DMARCDomainGroupRequest) (string, error) {
	normalizeDMARCDomainGroupRequest(&request)
	var response IDResponse
	if err := c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/domain-groups", nil, request, &response); err != nil {
		return "", err
	}
	if response.ID == "" {
		return "", fmt.Errorf("mimecast: create DMARC domain group returned no ID")
	}
	return response.ID, nil
}

// GetManagedDMARCDomainGroup retrieves one domain group by ID.
func (c *Client) GetManagedDMARCDomainGroup(ctx context.Context, id string) (ManagedDMARCDomainGroup, error) {
	var response ManagedDMARCDomainGroup
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/domain-groups/"+url.PathEscape(id), nil, nil, &response)
	normalizeManagedDMARCDomainGroup(&response)
	return response, err
}

// ListManagedDMARCDomainGroups retrieves every domain group using cursor pagination.
func (c *Client) ListManagedDMARCDomainGroups(ctx context.Context) ([]ManagedDMARCDomainGroup, error) {
	type page struct {
		Items []ManagedDMARCDomainGroup `json:"items"`
		Meta  PageMeta                  `json:"meta"`
	}
	items := make([]ManagedDMARCDomainGroup, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/domain-groups", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	for index := range items {
		normalizeManagedDMARCDomainGroup(&items[index])
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

// UpdateManagedDMARCDomainGroup replaces all mutable domain-group fields.
func (c *Client) UpdateManagedDMARCDomainGroup(ctx context.Context, id string, request DMARCDomainGroupRequest) error {
	normalizeDMARCDomainGroupRequest(&request)
	return c.Do(ctx, http.MethodPut, dmarcAnalyzerV1Path+"/domain-groups/"+url.PathEscape(id), nil, request, nil)
}

// DeleteManagedDMARCDomainGroup deletes one domain group.
func (c *Client) DeleteManagedDMARCDomainGroup(ctx context.Context, id string) error {
	query := url.Values{}
	query.Set("id", id)
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/domain-groups", query, nil, nil)
}

func normalizeManagedDMARCDomainGroup(group *ManagedDMARCDomainGroup) {
	if group == nil {
		return
	}
	sort.SliceStable(group.IncludedDomains, func(i, j int) bool { return group.IncludedDomains[i].ID < group.IncludedDomains[j].ID })
	sort.Strings(group.IncludeDomainsRegex)
}

func normalizeDMARCDomainGroupRequest(request *DMARCDomainGroupRequest) {
	if request == nil {
		return
	}
	if request.IncludedDomains != nil {
		sort.Strings(*request.IncludedDomains)
	}
	if request.IncludeDomainsRegex != nil {
		sort.Strings(*request.IncludeDomainsRegex)
	}
}

// DMARCComplianceTrigger models a single compliance-monitor threshold trigger.
type DMARCComplianceTrigger struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	Threshold *int64 `json:"threshold,omitempty"`
	Interval  string `json:"interval,omitempty"`
}

// DMARCNotificationTriggerConfig is the union of the two official trigger-config shapes.
type DMARCNotificationTriggerConfig struct {
	IsIndividualDomainAlert *bool                   `json:"isIndividualDomainAlert,omitempty"`
	InvalidMessageTrigger   *DMARCComplianceTrigger `json:"invalidMessageTrigger,omitempty"`
	DMARCComplianceTrigger  *DMARCComplianceTrigger `json:"dmarcComplianceTrigger,omitempty"`
	ForensicMessageTrigger  *DMARCComplianceTrigger `json:"forensicMessageTrigger,omitempty"`
	DMARCRecords            *bool                   `json:"dmarcRecords,omitempty"`
	DKIMRecords             *bool                   `json:"dkimRecords,omitempty"`
	SPFRecords              *bool                   `json:"spfRecords,omitempty"`
}

// DMARCNotificationRequest models the official notification request.
type DMARCNotificationRequest struct {
	Emails        []string                        `json:"email"`
	Frequency     string                          `json:"frequency,omitempty"`
	Domains       *[]string                       `json:"domains,omitempty"`
	Groups        *[]string                       `json:"groups,omitempty"`
	TriggerConfig *DMARCNotificationTriggerConfig `json:"triggerConfig,omitempty"`
}

// ManagedDMARCNotification is the typed notification response.
type ManagedDMARCNotification struct {
	ID            string                          `json:"id,omitempty"`
	Emails        []string                        `json:"email,omitempty"`
	Frequency     string                          `json:"frequency,omitempty"`
	Type          string                          `json:"type,omitempty"`
	Domains       []DMARCDomainReference          `json:"domains,omitempty"`
	Groups        []DMARCDomainReference          `json:"groups,omitempty"`
	TriggerConfig *DMARCNotificationTriggerConfig `json:"triggerConfig,omitempty"`
	NextTrigger   string                          `json:"nextTrigger,omitempty"`
}

// CreateManagedDMARCNotification creates a notification of the supplied type.
func (c *Client) CreateManagedDMARCNotification(ctx context.Context, notificationType string, request DMARCNotificationRequest) (ManagedDMARCNotification, error) {
	normalizeDMARCNotificationRequest(&request)
	var response ManagedDMARCNotification
	err := c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/notifications/"+url.PathEscape(notificationType), nil, request, &response)
	normalizeManagedDMARCNotification(&response)
	return response, err
}

// GetManagedDMARCNotification retrieves one notification by ID.
func (c *Client) GetManagedDMARCNotification(ctx context.Context, id string) (ManagedDMARCNotification, error) {
	var response ManagedDMARCNotification
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/notifications/"+url.PathEscape(id), nil, nil, &response)
	normalizeManagedDMARCNotification(&response)
	return response, err
}

// ListManagedDMARCNotifications retrieves every notification using cursor pagination.
func (c *Client) ListManagedDMARCNotifications(ctx context.Context) ([]ManagedDMARCNotification, error) {
	type page struct {
		Items []ManagedDMARCNotification `json:"items"`
		Meta  PageMeta                   `json:"meta"`
	}
	items := make([]ManagedDMARCNotification, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/notifications", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	for index := range items {
		normalizeManagedDMARCNotification(&items[index])
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

// UpdateManagedDMARCNotification replaces all mutable notification fields.
func (c *Client) UpdateManagedDMARCNotification(ctx context.Context, id string, request DMARCNotificationRequest) error {
	normalizeDMARCNotificationRequest(&request)
	return c.Do(ctx, http.MethodPut, dmarcAnalyzerV1Path+"/notifications/"+url.PathEscape(id), nil, request, nil)
}

// DeleteManagedDMARCNotification deletes one notification.
func (c *Client) DeleteManagedDMARCNotification(ctx context.Context, id string) error {
	query := url.Values{}
	query.Set("ids", id)
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/notifications", query, nil, nil)
}

func normalizeManagedDMARCNotification(notification *ManagedDMARCNotification) {
	if notification == nil {
		return
	}
	sort.Strings(notification.Emails)
	sort.SliceStable(notification.Domains, func(i, j int) bool { return notification.Domains[i].ID < notification.Domains[j].ID })
	sort.SliceStable(notification.Groups, func(i, j int) bool { return notification.Groups[i].ID < notification.Groups[j].ID })
}

func normalizeDMARCNotificationRequest(request *DMARCNotificationRequest) {
	if request == nil {
		return
	}
	sort.Strings(request.Emails)
	if request.Domains != nil {
		sort.Strings(*request.Domains)
	}
	if request.Groups != nil {
		sort.Strings(*request.Groups)
	}
}

// ManagedDMARCDefinition models the official DMARC definition fields.
type ManagedDMARCDefinition struct {
	Version                 string    `json:"version"`
	Policy                  string    `json:"policy"`
	SubdomainPolicy         string    `json:"subdomainPolicy,omitempty"`
	RUAAddresses            *[]string `json:"ruaAddresses,omitempty"`
	RUFAddresses            *[]string `json:"rufAddresses,omitempty"`
	DKIMAlignment           string    `json:"dkimAlignment,omitempty"`
	SPFAlignment            string    `json:"spfAlignment,omitempty"`
	ReportInterval          *int64    `json:"reportInterval,omitempty"`
	FailureReportingOptions string    `json:"failureReportingOptions,omitempty"`
	FailureReportFormat     string    `json:"failureReportFormat,omitempty"`
	Percentage              *int64    `json:"percentage,omitempty"`
}

// DMARCPolicyPresetRequest models the official create and update request.
type DMARCPolicyPresetRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ManagedDMARCDefinition
}

// ManagedDMARCPolicyPreset is the typed policy-preset response.
type ManagedDMARCPolicyPreset struct {
	ID              string `json:"id,omitempty"`
	Name            string `json:"name,omitempty"`
	IsDefaultPolicy *bool  `json:"isDefaultPolicy,omitempty"`
	Description     string `json:"description,omitempty"`
	ManagedDMARCDefinition
}

// CreateManagedDMARCPolicyPreset creates a policy preset and returns the API response.
func (c *Client) CreateManagedDMARCPolicyPreset(ctx context.Context, request DMARCPolicyPresetRequest) (ManagedDMARCPolicyPreset, error) {
	normalizeDMARCPolicyPresetRequest(&request)
	var response ManagedDMARCPolicyPreset
	err := c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/dmarc-policy-preset", nil, request, &response)
	normalizeManagedDMARCPolicyPreset(&response)
	return response, err
}

// GetManagedDMARCPolicyPreset retrieves a preset through the paginated list operation.
func (c *Client) GetManagedDMARCPolicyPreset(ctx context.Context, id string) (ManagedDMARCPolicyPreset, error) {
	query := url.Values{}
	query.Set("id", id)
	items, err := c.listManagedDMARCPolicyPresets(ctx, query)
	if err != nil {
		return ManagedDMARCPolicyPreset{}, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return ManagedDMARCPolicyPreset{}, &APIError{StatusCode: http.StatusNotFound, Method: http.MethodGet, Path: dmarcAnalyzerV1Path + "/dmarc-policy-preset"}
}

// ListManagedDMARCPolicyPresets retrieves every policy preset using cursor pagination.
func (c *Client) ListManagedDMARCPolicyPresets(ctx context.Context) ([]ManagedDMARCPolicyPreset, error) {
	return c.listManagedDMARCPolicyPresets(ctx, nil)
}

func (c *Client) listManagedDMARCPolicyPresets(ctx context.Context, query url.Values) ([]ManagedDMARCPolicyPreset, error) {
	type page struct {
		Items []ManagedDMARCPolicyPreset `json:"items"`
		Meta  PageMeta                   `json:"meta"`
	}
	items := make([]ManagedDMARCPolicyPreset, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/dmarc-policy-preset", query, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	for index := range items {
		normalizeManagedDMARCPolicyPreset(&items[index])
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

// UpdateManagedDMARCPolicyPreset replaces all mutable preset fields.
func (c *Client) UpdateManagedDMARCPolicyPreset(ctx context.Context, id string, request DMARCPolicyPresetRequest) error {
	normalizeDMARCPolicyPresetRequest(&request)
	return c.Do(ctx, http.MethodPut, dmarcAnalyzerV1Path+"/dmarc-policy-preset/"+url.PathEscape(id), nil, request, nil)
}

// DeleteManagedDMARCPolicyPreset deletes one policy preset.
func (c *Client) DeleteManagedDMARCPolicyPreset(ctx context.Context, id string) error {
	query := url.Values{}
	query.Set("id", id)
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/dmarc-policy-preset", query, nil, nil)
}

func normalizeManagedDMARCPolicyPreset(preset *ManagedDMARCPolicyPreset) {
	if preset == nil {
		return
	}
	if preset.RUAAddresses != nil {
		sort.Strings(*preset.RUAAddresses)
	}
	if preset.RUFAddresses != nil {
		sort.Strings(*preset.RUFAddresses)
	}
}

func normalizeDMARCPolicyPresetRequest(request *DMARCPolicyPresetRequest) {
	if request == nil {
		return
	}
	if request.RUAAddresses != nil {
		sort.Strings(*request.RUAAddresses)
	}
	if request.RUFAddresses != nil {
		sort.Strings(*request.RUFAddresses)
	}
}
