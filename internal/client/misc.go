package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

type ProfileGroup struct {
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
	ParentID    string `json:"parentId,omitempty"`
	UserCount   int64  `json:"userCount,omitempty"`
	GroupCount  int64  `json:"groupCount,omitempty"`
}

type GroupMember struct {
	EmailAddress string `json:"emailAddress,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Name         string `json:"name,omitempty"`
	Internal     *bool  `json:"internal,omitempty"`
	Type         string `json:"type,omitempty"`
	Note         string `json:"note,omitempty"`
}

type PendingDomain struct {
	ID              string `json:"id,omitempty"`
	Domain          string `json:"domain,omitempty"`
	Token           string `json:"token,omitempty"`
	Local           *bool  `json:"local,omitempty"`
	InboundType     string `json:"inboundType,omitempty"`
	CreatedDateTime string `json:"createdDateTime,omitempty"`
	ExpiryDateTime  string `json:"expiryDateTime,omitempty"`
	SendOnly        *bool  `json:"sendOnly,omitempty"`
}

type Connector struct {
	ID              string           `json:"id,omitempty"`
	Name            string           `json:"name,omitempty"`
	Description     string           `json:"description,omitempty"`
	Product         ConnectorProduct `json:"product,omitempty"`
	Provider        string           `json:"provider,omitempty"`
	Status          string           `json:"status,omitempty"`
	CreatedDateTime string           `json:"createdDateTime,omitempty"`
	UpdatedDateTime string           `json:"updatedDateTime,omitempty"`
}

type ConnectorProduct struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Code        string `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
}

type JournalingService struct {
	ID                              string         `json:"id,omitempty"`
	Description                     string         `json:"description,omitempty"`
	Enabled                         *bool          `json:"enabled,omitempty"`
	MessageFormat                   string         `json:"messageFormat,omitempty"`
	RemoveJournalHeaders            *bool          `json:"removeJournalHeaders,omitempty"`
	JournalNonInternalAddresses     *bool          `json:"journalNonInternalAddresses,omitempty"`
	JournalUnknownInternalAddresses *bool          `json:"journalUnknownInternalAddresses,omitempty"`
	TransferProtocol                string         `json:"transferProtocol,omitempty"`
	SMTPJournalingConnection        map[string]any `json:"smtpJournalingConnection,omitempty"`
	POP3JournalingConnection        map[string]any `json:"pop3JournalingConnection,omitempty"`
	StatusInfo                      map[string]any `json:"statusInfo,omitempty"`
	QueueSize                       int64          `json:"queueSize,omitempty"`
}

type CloudIntegratedPolicy struct {
	PolicyID        string                          `json:"policyId,omitempty"`
	AccountID       string                          `json:"accountId,omitempty"`
	Name            string                          `json:"name,omitempty"`
	Description     string                          `json:"description,omitempty"`
	ProtectionMode  string                          `json:"protectionMode,omitempty"`
	Targets         *CloudIntegratedTargets         `json:"targets,omitempty"`
	Actions         *CloudIntegratedActions         `json:"actions,omitempty"`
	Alerts          *CloudIntegratedAlerts          `json:"alerts,omitempty"`
	SecurityEngines *CloudIntegratedSecurityEngines `json:"securityEngines,omitempty"`
}

type CloudIntegratedTargets struct {
	Senders      *CloudIntegratedRouteTarget `json:"senders,omitempty"`
	Recipients   *CloudIntegratedRouteTarget `json:"recipients,omitempty"`
	Exceptions   *CloudIntegratedException   `json:"exceptions,omitempty"`
	AddressMatch string                      `json:"addressMatch,omitempty"`
}

type CloudIntegratedRouteTarget struct {
	Route   string                 `json:"route"`
	Emails  []string               `json:"emails,omitempty"`
	Groups  []CloudIntegratedGroup `json:"groups,omitempty"`
	Domains []string               `json:"domains,omitempty"`
}

type CloudIntegratedException struct {
	Emails  []string               `json:"emails,omitempty"`
	Groups  []CloudIntegratedGroup `json:"groups,omitempty"`
	Domains []string               `json:"domains,omitempty"`
}

type CloudIntegratedGroup struct {
	ID string `json:"id"`
}

type CloudIntegratedActions struct {
	Malware       string `json:"malware,omitempty"`
	Phishing      string `json:"phishing,omitempty"`
	Untrustworthy string `json:"untrustworthy,omitempty"`
	Spam          string `json:"spam,omitempty"`
}

type CloudIntegratedAlerts struct {
	Malware       *bool `json:"malware,omitempty"`
	Phishing      *bool `json:"phishing,omitempty"`
	Untrustworthy *bool `json:"untrustworthy,omitempty"`
	Spam          *bool `json:"spam,omitempty"`
}

type CloudIntegratedSecurityEngines struct {
	URLClick      *CloudIntegratedURLClickEngine      `json:"urlClick,omitempty"`
	Phishing      *CloudIntegratedPhishingEngine      `json:"phishing,omitempty"`
	Impersonation *CloudIntegratedImpersonationEngine `json:"impersonation,omitempty"`
	Attachments   *CloudIntegratedAttachmentsEngine   `json:"attachments,omitempty"`
}

type CloudIntegratedURLClickEngine struct {
	Sensitivity              string `json:"sensitivity,omitempty"`
	ScanURLsInAttachment     *bool  `json:"scanUrlsInAttachment,omitempty"`
	RewriteEnabled           *bool  `json:"rewriteEnabled,omitempty"`
	RewriteMode              string `json:"rewriteMode,omitempty"`
	ForceSecureConnection    *bool  `json:"forceSecureConnection,omitempty"`
	BlockDangerousExtensions *bool  `json:"blockDangerousExtensions,omitempty"`
	UserIdentification       string `json:"userIdentification,omitempty"`
	BIUnclassifiedURLs       *bool  `json:"biUnclassifiedUrls,omitempty"`
	BIAdminViewing           *bool  `json:"biAdminViewing,omitempty"`
	BIEnterText              *bool  `json:"biEnterText,omitempty"`
	BIPasteText              *bool  `json:"biPasteText,omitempty"`
	BICopyText               *bool  `json:"biCopyText,omitempty"`
	ScanOutboundEmails       *bool  `json:"scanOutboundEmails,omitempty"`
}

type CloudIntegratedPhishingEngine struct {
	SensitivityPhishingHigh      *int64 `json:"sensitivityPhishingHigh,omitempty"`
	SensitivityUntrustworthyHigh *int64 `json:"sensitivityUntrustworthyHigh,omitempty"`
	ScanOutboundEmails           *bool  `json:"scanOutboundEmails,omitempty"`
}

type CloudIntegratedImpersonationEngine struct {
	CodeBreakerStatus string `json:"codeBreakerStatus,omitempty"`
	ReportingStatus   string `json:"reportingStatus,omitempty"`
	SilencerStatus    string `json:"silencerStatus,omitempty"`
}

type CloudIntegratedAttachmentsEngine struct {
	SandboxEnabled     *bool  `json:"sandboxEnabled,omitempty"`
	UnreadableArchives string `json:"unreadableArchives,omitempty"`
}

// cloudIntegratedPolicyWrite mirrors the create and update request schemas.
// PolicyID and AccountID are response-only and must never be echoed to either
// endpoint.
type cloudIntegratedPolicyWrite struct {
	Name            string                          `json:"name"`
	Description     string                          `json:"description,omitempty"`
	ProtectionMode  string                          `json:"protectionMode"`
	Targets         *CloudIntegratedTargets         `json:"targets"`
	Actions         *CloudIntegratedActions         `json:"actions,omitempty"`
	Alerts          *CloudIntegratedAlerts          `json:"alerts,omitempty"`
	SecurityEngines *CloudIntegratedSecurityEngines `json:"securityEngines,omitempty"`
}

func (c *Client) CreateProfileGroup(ctx context.Context, group ProfileGroup) (string, error) {
	var out IDResponse
	err := c.Do(ctx, http.MethodPost, "/directory/cloud-gateway/v1/groups", nil, group, &out)
	if err == nil && out.ID == "" {
		err = fmt.Errorf("mimecast: create profile group response did not include an ID")
	}
	return out.ID, err
}

func (c *Client) UpdateProfileGroup(ctx context.Context, group ProfileGroup) error {
	return c.Do(ctx, http.MethodPost, "/api/directory/update-group", nil, map[string]any{"data": []ProfileGroup{group}}, nil)
}

func (c *Client) DeleteProfileGroup(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/api/directory/delete-group", nil, map[string]any{"data": []ProfileGroup{{ID: id}}}, nil)
}

func (c *Client) GetProfileGroup(ctx context.Context, id string) (ProfileGroup, error) {
	var out ProfileGroup
	err := c.Do(ctx, http.MethodGet, "/directory/cloud-gateway/v1/groups/"+url.PathEscape(id), nil, nil, &out)
	out.ID = id
	return out, err
}

func (c *Client) ListProfileGroups(ctx context.Context) ([]ProfileGroup, error) {
	type page struct {
		Groups []ProfileGroup `json:"groups"`
		Meta   PageMeta       `json:"meta"`
	}
	items := make([]ProfileGroup, 0)
	err := c.DoAllPages(ctx, "/directory/cloud-gateway/v1/groups", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Groups...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func (c *Client) AddProfileGroupMembers(ctx context.Context, id string, members []GroupMember) error {
	var out groupMemberMutationResponse
	if err := c.Do(ctx, http.MethodPost, "/directory/cloud-gateway/v1/groups/"+url.PathEscape(id)+"/members", nil, map[string]any{"groupMembers": members}, &out); err != nil {
		return err
	}
	return out.validate(len(members))
}

func (c *Client) RemoveProfileGroupMembers(ctx context.Context, id string, members []GroupMember) error {
	var out groupMemberMutationResponse
	if err := c.Do(ctx, http.MethodPost, "/directory/cloud-gateway/v1/groups/"+url.PathEscape(id)+"/remove-members", nil, map[string]any{"groupMembers": members}, &out); err != nil {
		return err
	}
	return out.validate(len(members))
}

func (c *Client) ListProfileGroupMembers(ctx context.Context, id string) ([]GroupMember, error) {
	type page struct {
		GroupMembers []GroupMember `json:"groupMembers"`
		Meta         PageMeta      `json:"meta"`
	}
	items := make([]GroupMember, 0)
	path := "/directory/cloud-gateway/v1/groups/" + url.PathEscape(id) + "/members"
	err := c.DoAllPages(ctx, path, nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).GroupMembers...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].EmailAddress != items[j].EmailAddress {
			return items[i].EmailAddress < items[j].EmailAddress
		}
		return items[i].Domain < items[j].Domain
	})
	return items, err
}

type groupMemberMutationResponse struct {
	Results []struct {
		Success *bool `json:"success,omitempty"`
	} `json:"results,omitempty"`
}

func (r groupMemberMutationResponse) validate(requested int) error {
	if len(r.Results) == 0 {
		return nil
	}
	if len(r.Results) != requested {
		return fmt.Errorf("mimecast: group membership operation returned %d results for %d requested members", len(r.Results), requested)
	}
	for _, result := range r.Results {
		if result.Success == nil || !*result.Success {
			return fmt.Errorf("mimecast: one or more group membership items failed")
		}
	}
	return nil
}

func (c *Client) ListPendingDomains(ctx context.Context) ([]PendingDomain, error) {
	type page struct {
		Domains []PendingDomain `json:"domains"`
		Meta    PageMeta        `json:"meta"`
	}
	items := make([]PendingDomain, 0)
	err := c.DoAllPages(ctx, "/domain/cloud-gateway/v1/pending-domains", nil, func() any { return &page{} }, func(value any) error {
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

func (c *Client) PutOutboundIPAddresses(ctx context.Context, ips []string) error {
	canonical := append([]string(nil), ips...)
	sort.Strings(canonical)
	return c.Do(ctx, http.MethodPut, "/email/cloud-gateway/v1/outbound-ip-addresses", nil, map[string]any{"outboundIpAddresses": canonical}, nil)
}

type outboundIPAddresses []string

// UnmarshalJSON accepts both the string array in the published contract and
// the object entries returned by the live API.
func (addresses *outboundIPAddresses) UnmarshalJSON(data []byte) error {
	var strings []string
	if err := json.Unmarshal(data, &strings); err == nil {
		*addresses = strings
		return nil
	}

	var objects []struct {
		OutboundIPAddress string `json:"outboundIpAddress"`
	}
	if err := json.Unmarshal(data, &objects); err != nil {
		return fmt.Errorf("mimecast: decode outbound IP address list")
	}

	values := make([]string, 0, len(objects))
	for _, object := range objects {
		if object.OutboundIPAddress == "" {
			return fmt.Errorf("mimecast: outbound IP address entry is missing outboundIpAddress")
		}
		values = append(values, object.OutboundIPAddress)
	}
	*addresses = values
	return nil
}

func (c *Client) GetOutboundIPAddresses(ctx context.Context) ([]string, error) {
	var out struct {
		OutboundIPAddresses outboundIPAddresses `json:"outboundIpAddresses"`
	}
	err := c.Do(ctx, http.MethodGet, "/email/cloud-gateway/v1/outbound-ip-addresses", nil, nil, &out)
	sort.Strings(out.OutboundIPAddresses)
	return out.OutboundIPAddresses, err
}

func (c *Client) DeleteOutboundIPAddresses(ctx context.Context) error {
	return c.Do(ctx, http.MethodDelete, "/email/cloud-gateway/v1/outbound-ip-addresses", nil, nil, nil)
}

func (c *Client) ListConnectors(ctx context.Context) ([]Connector, error) {
	type page struct {
		Connectors []Connector `json:"connectors"`
		Meta       PageMeta    `json:"meta"`
	}
	items := make([]Connector, 0)
	err := c.DoAllPages(ctx, "/connector/cloud-gateway/v1/connectors", nil, func() any { return &page{} }, func(value any) error {
		items = append(items, value.(*page).Connectors...)
		return nil
	})
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, err
}

func (c *Client) GetJournalingService(ctx context.Context, id string) (JournalingService, error) {
	var out JournalingService
	err := c.Do(ctx, http.MethodGet, "/journaling/cloud-gateway/v1/services/"+url.PathEscape(id), nil, nil, &out)
	return out, err
}

func (c *Client) ListJournalingServices(ctx context.Context) ([]JournalingServiceRead, error) {
	type page struct {
		Services           []JournalingServiceRead `json:"services"`
		JournalingServices []JournalingServiceRead `json:"journalingServices"`
		Meta               PageMeta                `json:"meta"`
	}
	items := make([]JournalingServiceRead, 0)
	err := c.DoAllPages(ctx, "/journaling/cloud-gateway/v1/services", nil, func() any { return &page{} }, func(value any) error {
		page := value.(*page)
		if len(page.JournalingServices) > 0 {
			items = append(items, page.JournalingServices...)
		} else {
			items = append(items, page.Services...)
		}
		return nil
	})
	for i := range items {
		if connection := items[i].SMTPJournalingConnection; connection != nil {
			if connection.IPRanges != nil {
				sort.Strings(*connection.IPRanges)
			}
			if connection.Hostnames != nil {
				sort.Strings(*connection.Hostnames)
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, right := "", ""
		if items[i].ID != nil {
			left = *items[i].ID
		}
		if items[j].ID != nil {
			right = *items[j].ID
		}
		return left < right
	})
	return items, err
}

// Journaling mutations are compatibility shims only. The Terraform provider
// does not register this resource until secrets have a typed write-only model.
func (c *Client) CreateJournalingService(ctx context.Context, in JournalingService) (string, error) {
	var out IDResponse
	err := c.Do(ctx, http.MethodPost, "/journaling/cloud-gateway/v1/services", nil, in, &out)
	return out.ID, err
}

func (c *Client) UpdateJournalingService(ctx context.Context, id string, in JournalingService) error {
	return c.Do(ctx, http.MethodPatch, "/journaling/cloud-gateway/v1/services/"+url.PathEscape(id), nil, in, nil)
}

func (c *Client) DeleteJournalingService(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/journaling/cloud-gateway/v1/services/"+url.PathEscape(id), nil, nil, nil)
}

func (c *Client) CreateCloudIntegratedPolicy(ctx context.Context, in CloudIntegratedPolicy) (string, error) {
	in.canonicalize()
	var out IDResponsePolicy
	err := c.Do(ctx, http.MethodPost, "/email/cloud-integrated/v1/policies", nil, in.writeRequest(), &out)
	if out.PolicyID != "" {
		return out.PolicyID, err
	}
	return out.ID, err
}

func (c *Client) GetCloudIntegratedPolicy(ctx context.Context, id string) (CloudIntegratedPolicy, error) {
	var out CloudIntegratedPolicy
	err := c.Do(ctx, http.MethodGet, "/email/cloud-integrated/v1/policies/"+url.PathEscape(id), nil, nil, &out)
	out.canonicalize()
	return out, err
}

func (c *Client) GetCloudIntegratedDefaultPolicy(ctx context.Context) (CloudIntegratedPolicy, error) {
	var out CloudIntegratedPolicy
	err := c.Do(ctx, http.MethodGet, "/email/cloud-integrated/v1/policies/default-policy", nil, nil, &out)
	out.canonicalize()
	return out, err
}

func (c *Client) UpdateCloudIntegratedPolicy(ctx context.Context, id string, in CloudIntegratedPolicy) error {
	in.canonicalize()
	return c.Do(ctx, http.MethodPatch, "/email/cloud-integrated/v1/policies/"+url.PathEscape(id), nil, in.writeRequest(), nil)
}

func (c *Client) DeleteCloudIntegratedPolicy(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/email/cloud-integrated/v1/policies/"+url.PathEscape(id), nil, nil, nil)
}

func (p *CloudIntegratedPolicy) canonicalize() {
	if p == nil || p.Targets == nil {
		return
	}
	canonicalizeCloudRouteTarget(p.Targets.Senders)
	canonicalizeCloudRouteTarget(p.Targets.Recipients)
	if p.Targets.Exceptions != nil {
		sort.Strings(p.Targets.Exceptions.Emails)
		sort.Strings(p.Targets.Exceptions.Domains)
		sort.SliceStable(p.Targets.Exceptions.Groups, func(i, j int) bool { return p.Targets.Exceptions.Groups[i].ID < p.Targets.Exceptions.Groups[j].ID })
	}
}

func (p CloudIntegratedPolicy) writeRequest() cloudIntegratedPolicyWrite {
	return cloudIntegratedPolicyWrite{
		Name: p.Name, Description: p.Description, ProtectionMode: p.ProtectionMode,
		Targets: p.Targets, Actions: p.Actions, Alerts: p.Alerts, SecurityEngines: p.SecurityEngines,
	}
}

func canonicalizeCloudRouteTarget(target *CloudIntegratedRouteTarget) {
	if target == nil {
		return
	}
	sort.Strings(target.Emails)
	sort.Strings(target.Domains)
	sort.SliceStable(target.Groups, func(i, j int) bool { return target.Groups[i].ID < target.Groups[j].ID })
}
