package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
)

// DMARCTTL accepts the numeric TTL returned by the service while tolerating
// the object type incorrectly declared by a small number of OpenAPI schemas.
type DMARCTTL struct {
	Value *int64
}

func (ttl *DMARCTTL) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) || len(trimmed) == 0 {
		ttl.Value = nil
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(trimmed, &number); err == nil {
		value, err := strconv.ParseInt(number.String(), 10, 64)
		if err == nil {
			ttl.Value = &value
			return nil
		}
	}
	var text string
	if err := json.Unmarshal(trimmed, &text); err == nil {
		value, err := strconv.ParseInt(text, 10, 64)
		if err == nil {
			ttl.Value = &value
			return nil
		}
	}
	// The portal currently declares TTL as an object but provides an integer
	// example. Unknown object shapes remain unset instead of breaking reads.
	if len(trimmed) > 0 && trimmed[0] == '{' {
		ttl.Value = nil
		return nil
	}
	return fmt.Errorf("mimecast: decode DMARC TTL")
}

type ManagedDMARCDelegatedDomain struct {
	ID                    string `json:"id,omitempty"`
	Domain                string `json:"domain,omitempty"`
	Hash                  string `json:"hash,omitempty"`
	DMARCDelegationStatus string `json:"dmarcDelegationStatus,omitempty"`
	DMARCPolicy           string `json:"dmarcPolicy,omitempty"`
	DKIMDelegationStatus  string `json:"dkimDelegationStatus,omitempty"`
	SPFDelegationStatus   string `json:"spfDelegationStatus,omitempty"`
	Details               string `json:"details,omitempty"`
}

func (c *Client) CreateManagedDMARCDelegatedDomain(ctx context.Context, managedDomainID string) (ManagedDMARCDelegatedDomain, error) {
	request := struct {
		Items []string `json:"items"`
	}{Items: []string{managedDomainID}}
	var response struct {
		Items []ManagedDMARCDelegatedDomain `json:"items"`
	}
	if err := c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/delegated-domains", nil, request, &response); err != nil {
		return ManagedDMARCDelegatedDomain{}, err
	}
	for _, item := range response.Items {
		if item.ID == managedDomainID {
			return item, nil
		}
	}
	return ManagedDMARCDelegatedDomain{}, fmt.Errorf("mimecast: create delegated DMARC domain returned no matching domain")
}

func (c *Client) ListManagedDMARCDelegatedDomains(ctx context.Context) ([]ManagedDMARCDelegatedDomain, error) {
	type page struct {
		Items []ManagedDMARCDelegatedDomain `json:"items"`
		Meta  PageMeta                      `json:"meta"`
	}
	items := make([]ManagedDMARCDelegatedDomain, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/delegated-domains", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func (c *Client) GetManagedDMARCDelegatedDomain(ctx context.Context, id string) (ManagedDMARCDelegatedDomain, error) {
	items, err := c.ListManagedDMARCDelegatedDomains(ctx)
	if err != nil {
		return ManagedDMARCDelegatedDomain{}, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return ManagedDMARCDelegatedDomain{}, &APIError{StatusCode: http.StatusNotFound, Method: http.MethodGet, Path: dmarcAnalyzerV1Path + "/delegated-domains"}
}

func (c *Client) DeleteManagedDMARCDelegatedDomain(ctx context.Context, id string) error {
	query := url.Values{}
	query.Set("id", id)
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/delegated-domains", query, nil, nil)
}

// AddManagedDMARCDomainGroupAssociation adds one managed domain to a group.
func (c *Client) AddManagedDMARCDomainGroupAssociation(ctx context.Context, groupID, domainID string) error {
	query := url.Values{}
	query.Set("domainId", domainID)
	return c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/domain-groups/"+url.PathEscape(groupID)+"/association", query, nil, nil)
}

// GetManagedDMARCDomainGroupAssociation reads membership through the parent group.
func (c *Client) GetManagedDMARCDomainGroupAssociation(ctx context.Context, groupID, domainID string) (DMARCDomainReference, error) {
	group, err := c.GetManagedDMARCDomainGroup(ctx, groupID)
	if err != nil {
		return DMARCDomainReference{}, err
	}
	for _, domain := range group.IncludedDomains {
		if domain.ID == domainID {
			return domain, nil
		}
	}
	return DMARCDomainReference{}, &APIError{
		StatusCode: http.StatusNotFound, Method: http.MethodGet,
		Path: dmarcAnalyzerV1Path + "/domain-groups/" + url.PathEscape(groupID) + "/association",
	}
}

// RemoveManagedDMARCDomainGroupAssociation removes one managed domain from a group.
func (c *Client) RemoveManagedDMARCDomainGroupAssociation(ctx context.Context, groupID, domainID string) error {
	query := url.Values{}
	query.Set("domainId", domainID)
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/domain-groups/"+url.PathEscape(groupID)+"/association", query, nil, nil)
}

type DMARCDNSRecordDetails struct {
	Host      string   `json:"host,omitempty"`
	Name      string   `json:"name,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"-"`
	Type      string   `json:"type,omitempty"`
	TTL       DMARCTTL `json:"ttl,omitempty"`
	Published *bool    `json:"published,omitempty"`
}

type managedDMARCDNSRecordDetailsAlias DMARCDNSRecordDetails

func (details *DMARCDNSRecordDetails) UnmarshalJSON(data []byte) error {
	var raw struct {
		managedDMARCDNSRecordDetailsAlias
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*details = DMARCDNSRecordDetails(raw.managedDMARCDNSRecordDetailsAlias)
	if len(raw.Value) == 0 || bytes.Equal(bytes.TrimSpace(raw.Value), []byte("null")) {
		return nil
	}
	if err := json.Unmarshal(raw.Value, &details.Value); err == nil {
		return nil
	}
	if err := json.Unmarshal(raw.Value, &details.Values); err == nil {
		sort.Strings(details.Values)
		return nil
	}
	return fmt.Errorf("mimecast: decode DMARC DNS record value")
}

type ManagedDMARCDefinitionResponse struct {
	Definition ManagedDMARCDefinition `json:"definition"`
	Record     struct {
		Host      string   `json:"host,omitempty"`
		Name      string   `json:"name,omitempty"`
		Value     string   `json:"value,omitempty"`
		Type      string   `json:"type,omitempty"`
		TTL       DMARCTTL `json:"ttl,omitempty"`
		Published *bool    `json:"published,omitempty"`
	} `json:"record"`
}

func (c *Client) CreateManagedDMARCDefinition(ctx context.Context, domainID, policyPresetID string) error {
	request := struct {
		PolicyPresetID string `json:"dmarcPolicyPresetId"`
	}{PolicyPresetID: policyPresetID}
	return c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dmarc", nil, request, nil)
}

func (c *Client) GetManagedDMARCDefinition(ctx context.Context, domainID string) (ManagedDMARCDefinitionResponse, error) {
	var response ManagedDMARCDefinitionResponse
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dmarc", nil, nil, &response)
	if response.Definition.RUAAddresses != nil {
		sort.Strings(*response.Definition.RUAAddresses)
	}
	if response.Definition.RUFAddresses != nil {
		sort.Strings(*response.Definition.RUFAddresses)
	}
	return response, err
}

func (c *Client) DeleteManagedDMARCDefinition(ctx context.Context, domainID string) error {
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dmarc", nil, nil, nil)
}

type DMARCDKIMPublicKey struct {
	Type string `json:"type,omitempty"`
	Data string `json:"data,omitempty"`
}

type ManagedDMARCDKIMDefinition struct {
	SourceID    string              `json:"sourceId,omitempty"`
	Version     string              `json:"version,omitempty"`
	Selector    string              `json:"selector"`
	RecordType  string              `json:"recordType"`
	Hostname    string              `json:"hostname,omitempty"`
	PublicKey   *DMARCDKIMPublicKey `json:"publicKey,omitempty"`
	ServiceType string              `json:"serviceType,omitempty"`
	Notes       string              `json:"notes,omitempty"`
	Flags       string              `json:"flags,omitempty"`
}

type ManagedDMARCDKIMDelegationDetails struct {
	Record struct {
		Name   string   `json:"name,omitempty"`
		Values []string `json:"value,omitempty"`
		Type   string   `json:"type,omitempty"`
		TTL    DMARCTTL `json:"ttl,omitempty"`
	} `json:"record"`
	Published *bool `json:"published,omitempty"`
}

func (c *Client) CreateManagedDMARCDKIMDefinition(ctx context.Context, domainID string, request ManagedDMARCDKIMDefinition) error {
	return c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dkim", nil, request, nil)
}

func (c *Client) GetManagedDMARCDKIMDefinition(ctx context.Context, domainID, selector string) (ManagedDMARCDKIMDefinition, error) {
	var response ManagedDMARCDKIMDefinition
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dkim/"+url.PathEscape(selector), nil, nil, &response)
	return response, err
}

func (c *Client) ListManagedDMARCDKIMDefinitions(ctx context.Context, domainID string) ([]ManagedDMARCDKIMDefinition, error) {
	type page struct {
		Items []ManagedDMARCDKIMDefinition `json:"items"`
		Meta  PageMeta                     `json:"meta"`
	}
	items := make([]ManagedDMARCDKIMDefinition, 0)
	path := dmarcAnalyzerV1Path + "/delegated-domains/" + url.PathEscape(domainID) + "/dkim"
	err := c.DoAllPages(ctx, path, nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].Selector < items[j].Selector })
	return items, err
}

func (c *Client) GetManagedDMARCDKIMDelegationDetails(ctx context.Context, domainID string) (ManagedDMARCDKIMDelegationDetails, error) {
	var response ManagedDMARCDKIMDelegationDetails
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dkim/details", nil, nil, &response)
	sort.Strings(response.Record.Values)
	return response, err
}

func (c *Client) UpdateManagedDMARCDKIMDefinition(ctx context.Context, domainID, selector string, request ManagedDMARCDKIMDefinition) error {
	return c.Do(ctx, http.MethodPut, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dkim/"+url.PathEscape(selector), nil, request, nil)
}

func (c *Client) DeleteManagedDMARCDKIMDefinition(ctx context.Context, domainID, selector string) error {
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/dkim/"+url.PathEscape(selector), nil, nil, nil)
}

type ManagedDMARCSPFTerm struct {
	Type     string `json:"type"`
	SourceID string `json:"sourceId,omitempty"`
	Label    string `json:"label,omitempty"`
	Target   string `json:"target"`
	CIDRIPv4 *int64 `json:"cidrIpV4,omitempty"`
	CIDRIPv6 *int64 `json:"cidrIpV6,omitempty"`
}

type ManagedDMARCSPFDefinition struct {
	Version      string                `json:"version"`
	Terms        []ManagedDMARCSPFTerm `json:"terms,omitempty"`
	AllQualifier string                `json:"allQualifier"`
}

type ManagedDMARCSPFDetails struct {
	Definition struct {
		Record struct {
			Name  string   `json:"name,omitempty"`
			Value string   `json:"value,omitempty"`
			Type  string   `json:"type,omitempty"`
			TTL   DMARCTTL `json:"ttl,omitempty"`
		} `json:"record"`
		Published  *bool  `json:"published,omitempty"`
		Normalized string `json:"normalized,omitempty"`
		Compressed string `json:"compressed,omitempty"`
	} `json:"definition"`
}

func (c *Client) PutManagedDMARCSPFDefinition(ctx context.Context, domainID string, request ManagedDMARCSPFDefinition) error {
	return c.Do(ctx, http.MethodPut, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/spf", nil, request, nil)
}

func (c *Client) GetManagedDMARCSPFDefinition(ctx context.Context, domainID string) (ManagedDMARCSPFDefinition, error) {
	var response struct {
		Definition ManagedDMARCSPFDefinition `json:"definition"`
	}
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/spf", nil, nil, &response)
	return response.Definition, err
}

func (c *Client) GetManagedDMARCSPFDetails(ctx context.Context, domainID string) (ManagedDMARCSPFDetails, error) {
	var response ManagedDMARCSPFDetails
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/spf/details", nil, nil, &response)
	return response, err
}

func (c *Client) DeleteManagedDMARCSPFDefinition(ctx context.Context, domainID string) error {
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/delegated-domains/"+url.PathEscape(domainID)+"/spf", nil, nil, nil)
}

type ManagedDMARCVendor struct {
	ID            string   `json:"id,omitempty"`
	Name          string   `json:"name,omitempty"`
	Instructions  string   `json:"instructions,omitempty"`
	DKIMSelectors []string `json:"dkimSelectors,omitempty"`
	SPFInclude    []string `json:"spfInclude,omitempty"`
	Hostnames     []string `json:"hostnames,omitempty"`
	Category      string   `json:"category,omitempty"`
	Status        string   `json:"status,omitempty"`
}

func (c *Client) GetManagedDMARCVendor(ctx context.Context, id string) (ManagedDMARCVendor, error) {
	var response ManagedDMARCVendor
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/sources/vendors/"+url.PathEscape(id), nil, nil, &response)
	normalizeManagedDMARCVendor(&response)
	return response, err
}

func (c *Client) ListManagedDMARCVendors(ctx context.Context) ([]ManagedDMARCVendor, error) {
	type page struct {
		Items []ManagedDMARCVendor `json:"items"`
		Meta  PageMeta             `json:"meta"`
	}
	items := make([]ManagedDMARCVendor, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/sources/vendors", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	for index := range items {
		normalizeManagedDMARCVendor(&items[index])
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func normalizeManagedDMARCVendor(vendor *ManagedDMARCVendor) {
	if vendor == nil {
		return
	}
	sort.Strings(vendor.DKIMSelectors)
	sort.Strings(vendor.SPFInclude)
	sort.Strings(vendor.Hostnames)
}

type ManagedDMARCUserFeatures struct {
	AggregateReports       *bool `json:"aggregateReports,omitempty"`
	AlertsAndNotifications *bool `json:"alertsAndNotifications,omitempty"`
	DNSDelegation          *bool `json:"dnsDelegation,omitempty"`
	DNSChecker             *bool `json:"dnsChecker,omitempty"`
	DNSGenerator           *bool `json:"dnsGenerator,omitempty"`
	DomainManagement       *bool `json:"domainManagement,omitempty"`
	EncryptionPGPKey       *bool `json:"encryptionPgpKey,omitempty"`
	ForensicReports        *bool `json:"forensicReports,omitempty"`
	Reporting              *bool `json:"reporting,omitempty"`
	TaskManager            *bool `json:"taskManager,omitempty"`
	Timeline               *bool `json:"timeline,omitempty"`
	TLSReports             *bool `json:"tlsReports,omitempty"`
	UserManagement         *bool `json:"userManagement,omitempty"`
	VendorManagement       *bool `json:"vendorManagement,omitempty"`
}

type ManagedDMARCUserRequest struct {
	UserName       string                    `json:"userName,omitempty"`
	UserEmail      string                    `json:"userEmail,omitempty"`
	UserPermission string                    `json:"userPermission,omitempty"`
	AllowedGroups  *[]string                 `json:"allowedGroups,omitempty"`
	Features       *ManagedDMARCUserFeatures `json:"features,omitempty"`
}

type ManagedDMARCUser struct {
	ID             string                    `json:"id,omitempty"`
	UserName       string                    `json:"userName,omitempty"`
	UserEmail      string                    `json:"userEmail,omitempty"`
	UserPermission string                    `json:"userPermission,omitempty"`
	AllowedGroups  []DMARCUserDomainGroup    `json:"allowedGroups,omitempty"`
	Features       *ManagedDMARCUserFeatures `json:"features,omitempty"`
}

type DMARCUserDomainGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

func (c *Client) CreateManagedDMARCUser(ctx context.Context, request ManagedDMARCUserRequest) (ManagedDMARCUser, error) {
	normalizeManagedDMARCUserRequest(&request)
	var response ManagedDMARCUser
	err := c.Do(ctx, http.MethodPost, dmarcAnalyzerV1Path+"/users", nil, request, &response)
	normalizeManagedDMARCUser(&response)
	return response, err
}

func (c *Client) GetManagedDMARCUser(ctx context.Context, idOrEmail string) (ManagedDMARCUser, error) {
	var response ManagedDMARCUser
	err := c.Do(ctx, http.MethodGet, dmarcAnalyzerV1Path+"/users/"+url.PathEscape(idOrEmail), nil, nil, &response)
	normalizeManagedDMARCUser(&response)
	return response, err
}

func (c *Client) ListManagedDMARCUsers(ctx context.Context) ([]ManagedDMARCUser, error) {
	type page struct {
		Items []ManagedDMARCUser `json:"items"`
		Meta  PageMeta           `json:"meta"`
	}
	items := make([]ManagedDMARCUser, 0)
	err := c.DoAllPages(ctx, dmarcAnalyzerV1Path+"/users", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Items...)
		return nil
	})
	for index := range items {
		normalizeManagedDMARCUser(&items[index])
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func (c *Client) UpdateManagedDMARCUser(ctx context.Context, id string, request ManagedDMARCUserRequest) error {
	request.UserName = ""
	request.UserEmail = ""
	normalizeManagedDMARCUserRequest(&request)
	return c.Do(ctx, http.MethodPut, dmarcAnalyzerV1Path+"/users/"+url.PathEscape(id), nil, request, nil)
}

func (c *Client) DeleteManagedDMARCUser(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, dmarcAnalyzerV1Path+"/users/"+url.PathEscape(id), nil, nil, nil)
}

func normalizeManagedDMARCUserRequest(request *ManagedDMARCUserRequest) {
	if request != nil && request.AllowedGroups != nil {
		sort.Strings(*request.AllowedGroups)
	}
}

func normalizeManagedDMARCUser(user *ManagedDMARCUser) {
	if user == nil {
		return
	}
	sort.SliceStable(user.AllowedGroups, func(i, j int) bool { return user.AllowedGroups[i].ID < user.AllowedGroups[j].ID })
}

func DMARCUserFeaturesEmpty(features *ManagedDMARCUserFeatures) bool {
	if features == nil {
		return true
	}
	return features.AggregateReports == nil && features.AlertsAndNotifications == nil && features.DNSDelegation == nil &&
		features.DNSChecker == nil && features.DNSGenerator == nil && features.DomainManagement == nil &&
		features.EncryptionPGPKey == nil && features.ForensicReports == nil && features.Reporting == nil &&
		features.TaskManager == nil && features.Timeline == nil && features.TLSReports == nil &&
		features.UserManagement == nil && features.VendorManagement == nil
}
