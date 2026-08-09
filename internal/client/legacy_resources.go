package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

const (
	addressAlterationSetPath         = "/api/policy/address-alteration/get-address-alteration-set"
	addressAlterationCreateDefPath   = "/api/policy/address-alteration/create-definition"
	addressAlterationGetDefPath      = "/api/policy/address-alteration/get-definition"
	addressAlterationDeleteDefPath   = "/api/policy/address-alteration/delete-definition"
	addressAlterationCreatePolicy    = "/api/policy/address-alteration/create-policy"
	addressAlterationGetPolicy       = "/api/policy/address-alteration/get-policy"
	addressAlterationUpdatePolicy    = "/api/policy/address-alteration/update-policy"
	addressAlterationDeletePolicy    = "/api/policy/address-alteration/delete-policy"
	webSecurityCreatePolicyPath      = "/api/policy/webwhiteurl/create-policy-with-targets"
	webSecurityGetPolicyPath         = "/api/policy/webwhiteurl/get-policy-with-targets"
	webSecurityUpdatePolicyPath      = "/api/policy/webwhiteurl/update-policy-with-targets"
	webSecurityDeletePolicyPath      = "/api/policy/webwhiteurl/delete-policy-with-targets"
	threatReportingSubscriptions     = "/threat-reporting/v1/subscriptions"
	defaultAddressAlterationSetDepth = int64(1)
)

// AddressAlterationSet is the typed, read-only folder returned by the legacy
// address-alteration set API. Folders are flattened by ListAddressAlterationSets
// so Terraform callers are not required to consume a recursive schema.
type AddressAlterationSet struct {
	ID          string                 `json:"id,omitempty"`
	Description string                 `json:"description,omitempty"`
	ParentID    string                 `json:"parentId,omitempty"`
	Source      string                 `json:"source,omitempty"`
	FolderCount int64                  `json:"folderCount,omitempty"`
	UserCount   int64                  `json:"userCount,omitempty"`
	Folders     []AddressAlterationSet `json:"folders,omitempty"`
}

type addressAlterationSetFilter struct {
	Depth    int64  `json:"depth,omitempty"`
	FolderID string `json:"folderId,omitempty"`
}

// ListAddressAlterationSets reads address-alteration sets using the documented
// POST-style read endpoint and returns a deterministic, de-duplicated flat list.
func (c *Client) ListAddressAlterationSets(ctx context.Context, folderID string, depth int64) ([]AddressAlterationSet, error) {
	if depth <= 0 {
		depth = defaultAddressAlterationSetDepth
	}
	fetch := func(id string) ([]AddressAlterationSet, error) {
		request := addressAlterationSetFilter{Depth: depth, FolderID: id}
		var out LegacyEnvelope[AddressAlterationSet]
		if err := c.DoRead(ctx, http.MethodPost, addressAlterationSetPath, nil, map[string]any{"data": []addressAlterationSetFilter{request}}, &out); err != nil {
			return nil, err
		}
		return out.Data, nil
	}

	byID := make(map[string]AddressAlterationSet)
	pending := make([]string, 0)
	queued := make(map[string]struct{})
	var add func(AddressAlterationSet)
	add = func(item AddressAlterationSet) {
		children := append([]AddressAlterationSet(nil), item.Folders...)
		item.Folders = nil
		if item.ID != "" {
			byID[item.ID] = item
			if item.FolderCount > int64(len(children)) {
				if _, exists := queued[item.ID]; !exists {
					queued[item.ID] = struct{}{}
					pending = append(pending, item.ID)
				}
			}
		}
		for _, child := range children {
			add(child)
		}
	}
	initial, err := fetch(folderID)
	if err != nil {
		return nil, err
	}
	for _, item := range initial {
		add(item)
	}
	for len(pending) > 0 {
		id := pending[0]
		pending = pending[1:]
		children, err := fetch(id)
		if err != nil {
			return nil, err
		}
		for _, item := range children {
			add(item)
		}
	}
	items := make([]AddressAlterationSet, 0, len(byID))
	for _, item := range byID {
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Description < items[j].Description
	})
	return items, nil
}

// AddressAlterationDefinition is one immutable address rewrite definition.
type AddressAlterationDefinition struct {
	ID              string `json:"id,omitempty"`
	FolderID        string `json:"folderId,omitempty"`
	AddressType     string `json:"addressType,omitempty"`
	OriginalAddress string `json:"originalAddress,omitempty"`
	NewAddress      string `json:"newAddress,omitempty"`
	Routing         string `json:"routing,omitempty"`
}

type addressAlterationDefinitionFilter struct {
	FolderID string `json:"folderId,omitempty"`
	Routing  string `json:"routing,omitempty"`
}

type legacyMutationResult struct {
	ID      string `json:"id,omitempty"`
	Success bool   `json:"success,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// CreateAddressAlterationDefinition creates exactly one definition and checks
// the documented per-item success indicator before returning its ID.
func (c *Client) CreateAddressAlterationDefinition(ctx context.Context, definition AddressAlterationDefinition) (string, error) {
	request := struct {
		AddressAlterations []AddressAlterationDefinition `json:"addressAlterations"`
		FolderID           string                        `json:"folderId,omitempty"`
	}{AddressAlterations: []AddressAlterationDefinition{{
		AddressType: definition.AddressType, OriginalAddress: definition.OriginalAddress,
		NewAddress: definition.NewAddress, Routing: definition.Routing,
	}}, FolderID: definition.FolderID}
	var out LegacyEnvelope[legacyMutationResult]
	if err := c.Do(ctx, http.MethodPost, addressAlterationCreateDefPath, nil, map[string]any{"data": []any{request}}, &out); err != nil {
		return "", err
	}
	if len(out.Data) != 1 || !out.Data[0].Success {
		return "", fmt.Errorf("mimecast: address alteration definition creation was not successful")
	}
	if out.Data[0].ID == "" {
		return "", fmt.Errorf("mimecast: address alteration definition creation response did not include an ID")
	}
	return out.Data[0].ID, nil
}

// GetAddressAlterationDefinition finds a definition by ID through the complete
// inventory path. The legacy read contract has no ID filter, and routing-only
// reads are not guaranteed to identify a definition's containing folder.
func (c *Client) GetAddressAlterationDefinition(ctx context.Context, id string) (AddressAlterationDefinition, error) {
	items, err := c.ListAddressAlterationDefinitions(ctx)
	if err != nil {
		return AddressAlterationDefinition{}, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return AddressAlterationDefinition{}, legacyNotFound(http.MethodPost, addressAlterationGetDefPath)
}

// ListAddressAlterationDefinitions discovers definitions through every
// documented routing value and every discoverable Address Alteration Set. The
// legacy endpoint has no pagination contract; each filter returns its complete
// items array. Folder-specific reads enrich the otherwise omitted folderId.
func (c *Client) ListAddressAlterationDefinitions(ctx context.Context) ([]AddressAlterationDefinition, error) {
	byID := make(map[string]AddressAlterationDefinition)
	add := func(items []AddressAlterationDefinition, folderID string) {
		for _, item := range items {
			if item.ID == "" {
				continue
			}
			if item.FolderID == "" {
				item.FolderID = folderID
			}
			if existing, ok := byID[item.ID]; ok && item.FolderID == "" {
				item.FolderID = existing.FolderID
			}
			byID[item.ID] = item
		}
	}
	fetch := func(filter addressAlterationDefinitionFilter) ([]AddressAlterationDefinition, error) {
		var out LegacyEnvelope[struct {
			Items []AddressAlterationDefinition `json:"items"`
		}]
		if err := c.DoRead(ctx, http.MethodPost, addressAlterationGetDefPath, nil, map[string]any{"data": []addressAlterationDefinitionFilter{filter}}, &out); err != nil {
			return nil, err
		}
		items := make([]AddressAlterationDefinition, 0)
		for _, result := range out.Data {
			items = append(items, result.Items...)
		}
		return items, nil
	}

	for _, routing := range []string{"all", "inbound", "outbound"} {
		items, err := fetch(addressAlterationDefinitionFilter{Routing: routing})
		if err != nil {
			return nil, err
		}
		add(items, "")
	}
	sets, err := c.ListAddressAlterationSets(ctx, "", defaultAddressAlterationSetDepth)
	if err != nil {
		return nil, err
	}
	for _, set := range sets {
		items, err := fetch(addressAlterationDefinitionFilter{FolderID: set.ID})
		if err != nil {
			return nil, err
		}
		add(items, set.ID)
	}

	items := make([]AddressAlterationDefinition, 0, len(byID))
	for _, item := range byID {
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

// DeleteAddressAlterationDefinition deletes one definition and checks the
// documented per-item success flag.
func (c *Client) DeleteAddressAlterationDefinition(ctx context.Context, id string) error {
	var out LegacyEnvelope[legacyMutationResult]
	if err := c.Do(ctx, http.MethodPost, addressAlterationDeleteDefPath, nil, map[string]any{"data": []any{map[string]string{"id": id}}}, &out); err != nil {
		return err
	}
	if len(out.Data) != 1 || out.Data[0].ID != id || !out.Data[0].Success {
		return fmt.Errorf("mimecast: address alteration definition deletion was not successful")
	}
	return nil
}

// LegacyPolicyAttribute is an address attribute target.
type LegacyPolicyAttribute struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// LegacyPolicyTarget tolerates the nested group object returned by reads while
// keeping groupId available for the documented write contract.
type LegacyPolicyTarget struct {
	Type         string                 `json:"type,omitempty"`
	Group        *TargetGroup           `json:"group,omitempty"`
	GroupID      string                 `json:"groupId,omitempty"`
	EmailDomain  string                 `json:"emailDomain,omitempty"`
	EmailAddress string                 `json:"emailAddress,omitempty"`
	Attribute    *LegacyPolicyAttribute `json:"attribute,omitempty"`
}

func (t LegacyPolicyTarget) ResolvedGroupID() string {
	if t.Group != nil && t.Group.ID != "" {
		return t.Group.ID
	}
	return t.GroupID
}

// LegacyPolicyConditions contains only condition arrays present in the current
// Policy Management write schemas.
type LegacyPolicyConditions struct {
	SourceIPs  []string `json:"sourceIPs,omitempty"`
	Hostnames  []string `json:"hostnames,omitempty"`
	SPFDomains []string `json:"spfDomains,omitempty"`
}

// LegacyPolicyScope is shared by address-alteration and Web Security target
// policies. Server-only timestamps and flattened read aliases are typed but are
// never sent unless they are part of the documented write schema.
type LegacyPolicyScope struct {
	Bidirectional *bool                   `json:"bidirectional,omitempty"`
	Comment       string                  `json:"comment,omitempty"`
	Conditions    *LegacyPolicyConditions `json:"conditions,omitempty"`
	CreateTime    string                  `json:"createTime,omitempty"`
	Description   string                  `json:"description,omitempty"`
	Enabled       *bool                   `json:"enabled,omitempty"`
	Enforced      *bool                   `json:"enforced,omitempty"`
	From          LegacyPolicyTarget      `json:"from,omitempty"`
	FromDate      string                  `json:"fromDate,omitempty"`
	FromEternal   *bool                   `json:"fromEternal,omitempty"`
	FromPart      string                  `json:"fromPart,omitempty"`
	FromType      string                  `json:"fromType,omitempty"`
	FromValue     string                  `json:"fromValue,omitempty"`
	LastUpdated   string                  `json:"lastUpdated,omitempty"`
	Override      *bool                   `json:"override,omitempty"`
	To            LegacyPolicyTarget      `json:"to,omitempty"`
	ToDate        string                  `json:"toDate,omitempty"`
	ToEternal     *bool                   `json:"toEternal,omitempty"`
	ToType        string                  `json:"toType,omitempty"`
	ToValue       string                  `json:"toValue,omitempty"`
}

// AddressAlterationPolicy applies an address-alteration set to a typed policy
// scope.
type AddressAlterationPolicy struct {
	ID                     string            `json:"id,omitempty"`
	AddressAlterationSetID string            `json:"addressAlterationSetId,omitempty"`
	Policy                 LegacyPolicyScope `json:"policy,omitempty"`
}

func (c *Client) CreateAddressAlterationPolicy(ctx context.Context, policy AddressAlterationPolicy) (string, error) {
	request := AddressAlterationPolicy{AddressAlterationSetID: policy.AddressAlterationSetID, Policy: legacyPolicyForWrite(policy.Policy, false)}
	var out LegacyEnvelope[AddressAlterationPolicy]
	if err := c.Do(ctx, http.MethodPost, addressAlterationCreatePolicy, nil, map[string]any{"data": []AddressAlterationPolicy{request}}, &out); err != nil {
		return "", err
	}
	if len(out.Data) != 1 || out.Data[0].ID == "" {
		return "", fmt.Errorf("mimecast: address alteration policy creation response did not include an ID")
	}
	return out.Data[0].ID, nil
}

func (c *Client) GetAddressAlterationPolicy(ctx context.Context, id string) (AddressAlterationPolicy, error) {
	var out LegacyEnvelope[AddressAlterationPolicy]
	if err := c.DoRead(ctx, http.MethodPost, addressAlterationGetPolicy, nil, map[string]any{"data": []any{map[string]string{"id": id}}}, &out); err != nil {
		return AddressAlterationPolicy{}, err
	}
	switch len(out.Data) {
	case 0:
		return AddressAlterationPolicy{}, legacyNotFound(http.MethodPost, addressAlterationGetPolicy)
	case 1:
		item := out.Data[0]
		// The filtered request identifies the policy. Mimecast can return a
		// different secure ID for the same object, so preserve the requested ID.
		item.ID = id
		canonicalizeLegacyPolicy(&item.Policy)
		return item, nil
	default:
		return AddressAlterationPolicy{}, fmt.Errorf("mimecast: address alteration policy lookup returned %d records; expected exactly one", len(out.Data))
	}
}

// ListAddressAlterationPolicies uses the documented omitted-id behaviour to
// return all policies. This legacy endpoint has no pagination fields.
func (c *Client) ListAddressAlterationPolicies(ctx context.Context) ([]AddressAlterationPolicy, error) {
	var out LegacyEnvelope[AddressAlterationPolicy]
	if err := c.DoRead(ctx, http.MethodPost, addressAlterationGetPolicy, nil, nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Data {
		canonicalizeLegacyPolicy(&out.Data[i].Policy)
	}
	sort.SliceStable(out.Data, func(i, j int) bool { return out.Data[i].ID < out.Data[j].ID })
	return out.Data, nil
}

func (c *Client) UpdateAddressAlterationPolicy(ctx context.Context, id string, policy AddressAlterationPolicy) error {
	request := AddressAlterationPolicy{ID: id, AddressAlterationSetID: policy.AddressAlterationSetID, Policy: legacyPolicyForWrite(policy.Policy, false)}
	var out LegacyEnvelope[AddressAlterationPolicy]
	if err := c.Do(ctx, http.MethodPost, addressAlterationUpdatePolicy, nil, map[string]any{"data": []AddressAlterationPolicy{request}}, &out); err != nil {
		return err
	}
	if len(out.Data) == 0 {
		return fmt.Errorf("mimecast: address alteration policy update returned no result")
	}
	return nil
}

func (c *Client) DeleteAddressAlterationPolicy(ctx context.Context, id string) error {
	var out LegacyEnvelope[legacyMutationResult]
	if err := c.Do(ctx, http.MethodPost, addressAlterationDeletePolicy, nil, map[string]any{"data": []any{map[string]string{"id": id}}}, &out); err != nil {
		return err
	}
	if len(out.Data) != 1 || out.Data[0].ID != id || !out.Data[0].Deleted {
		return fmt.Errorf("mimecast: address alteration policy deletion was not successful")
	}
	return nil
}

// WebSecurityURLAction is one allow/block action for a URL or domain.
type WebSecurityURLAction struct {
	ID     string `json:"id,omitempty"`
	Action string `json:"action"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

// WebSecurityTargetPolicy is one scoping policy contained by a Web Security
// URL policy. Reads wrap the policy body and return its own stable ID.
type WebSecurityTargetPolicy struct {
	ID        string `json:"id,omitempty"`
	Locations []struct {
		IP       string `json:"ip,omitempty"`
		Location string `json:"location,omitempty"`
	} `json:"locations,omitempty"`
	Policy LegacyPolicyScope `json:"policy"`
}

// WebSecurityURLPolicy contains target scopes and per-URL actions.
type WebSecurityURLPolicy struct {
	ID          string                    `json:"id,omitempty"`
	Description string                    `json:"description,omitempty"`
	Policies    []WebSecurityTargetPolicy `json:"policies,omitempty"`
	URLs        []WebSecurityURLAction    `json:"urls,omitempty"`
}

type webSecurityPolicyWrite struct {
	ID string `json:"id,omitempty"`
	LegacyPolicyScope
}

type webSecurityPolicyWriteRequest struct {
	ID          string                   `json:"id,omitempty"`
	Description string                   `json:"description,omitempty"`
	Policies    []webSecurityPolicyWrite `json:"policies"`
	URLs        []WebSecurityURLAction   `json:"urls,omitempty"`
}

func (p WebSecurityURLPolicy) writeRequest(includeID bool) webSecurityPolicyWriteRequest {
	request := webSecurityPolicyWriteRequest{Description: p.Description, URLs: append([]WebSecurityURLAction(nil), p.URLs...)}
	if includeID {
		request.ID = p.ID
	}
	request.Policies = make([]webSecurityPolicyWrite, 0, len(p.Policies))
	for _, target := range p.Policies {
		request.Policies = append(request.Policies, webSecurityPolicyWrite{ID: target.ID, LegacyPolicyScope: legacyPolicyForWrite(target.Policy, true)})
	}
	return request
}

func (c *Client) CreateWebSecurityURLPolicy(ctx context.Context, policy WebSecurityURLPolicy) (string, error) {
	request := policy.writeRequest(false)
	var out LegacyEnvelope[WebSecurityURLPolicy]
	if err := c.Do(ctx, http.MethodPost, webSecurityCreatePolicyPath, nil, map[string]any{"data": []webSecurityPolicyWriteRequest{request}}, &out); err != nil {
		return "", err
	}
	if len(out.Data) != 1 || out.Data[0].ID == "" {
		return "", fmt.Errorf("mimecast: Web Security URL policy creation response did not include an ID")
	}
	return out.Data[0].ID, nil
}

func (c *Client) GetWebSecurityURLPolicy(ctx context.Context, id string) (WebSecurityURLPolicy, error) {
	var out LegacyEnvelope[WebSecurityURLPolicy]
	if err := c.DoRead(ctx, http.MethodPost, webSecurityGetPolicyPath, nil, map[string]any{"data": []any{map[string]string{"id": id}}}, &out); err != nil {
		return WebSecurityURLPolicy{}, err
	}
	for _, item := range out.Data {
		if item.ID == id || item.ID == "" && len(out.Data) == 1 {
			item.ID = id
			canonicalizeWebSecurityPolicy(&item)
			return item, nil
		}
	}
	return WebSecurityURLPolicy{}, legacyNotFound(http.MethodPost, webSecurityGetPolicyPath)
}

func (c *Client) UpdateWebSecurityURLPolicy(ctx context.Context, id string, policy WebSecurityURLPolicy) error {
	policy.ID = id
	request := policy.writeRequest(true)
	var out LegacyEnvelope[WebSecurityURLPolicy]
	if err := c.Do(ctx, http.MethodPost, webSecurityUpdatePolicyPath, nil, map[string]any{"data": []webSecurityPolicyWriteRequest{request}}, &out); err != nil {
		return err
	}
	if len(out.Data) == 0 {
		return fmt.Errorf("mimecast: Web Security URL policy update returned no result")
	}
	return nil
}

func (c *Client) DeleteWebSecurityURLPolicy(ctx context.Context, id string) error {
	var out LegacyEnvelope[legacyMutationResult]
	if err := c.Do(ctx, http.MethodPost, webSecurityDeletePolicyPath, nil, map[string]any{"data": []any{map[string]string{"id": id}}}, &out); err != nil {
		return err
	}
	if len(out.Data) != 1 || out.Data[0].ID != id || !out.Data[0].Deleted {
		return fmt.Errorf("mimecast: Web Security URL policy deletion was not successful")
	}
	return nil
}

// ThreatReportingSubscription is the non-secret subscription state returned by
// Mimecast. ClientState is accepted on writes only and must never be persisted.
type ThreatReportingSubscription struct {
	SubscriptionID     string `json:"subscriptionId,omitempty"`
	NotificationURL    string `json:"notificationURL,omitempty"`
	ResourceType       string `json:"resourceType,omitempty"`
	CreationDateTime   string `json:"creationDateTime,omitempty"`
	ExpirationDateTime string `json:"expirationDateTime,omitempty"`
}

type threatReportingCreateRequest struct {
	ClientState     string `json:"clientState"`
	NotificationURL string `json:"notificationURL"`
	ResourceType    string `json:"resourceType"`
}

type threatReportingUpdateRequest struct {
	OldClientState string `json:"oldClientState"`
	ClientState    string `json:"clientState"`
}

type threatReportingSubscriptionList struct {
	Value []ThreatReportingSubscription `json:"value"`
}

// UnmarshalJSON accepts the current OpenAPI value wrapper and the bare array
// shown in Mimecast's webhook integration guide.
func (r *threatReportingSubscriptionList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		return json.Unmarshal(data, &r.Value)
	}
	type alias threatReportingSubscriptionList
	return json.Unmarshal(data, (*alias)(r))
}

func (c *Client) CreateThreatReportingSubscription(ctx context.Context, notificationURL, resourceType, clientState string) (ThreatReportingSubscription, error) {
	request := threatReportingCreateRequest{ClientState: clientState, NotificationURL: notificationURL, ResourceType: resourceType}
	var out ThreatReportingSubscription
	if err := c.Do(ctx, http.MethodPost, threatReportingSubscriptions, nil, request, &out); err != nil {
		return ThreatReportingSubscription{}, err
	}
	if out.SubscriptionID == "" {
		return ThreatReportingSubscription{}, fmt.Errorf("mimecast: threat-reporting subscription creation response did not include an ID")
	}
	return out, nil
}

func (c *Client) ListThreatReportingSubscriptions(ctx context.Context) ([]ThreatReportingSubscription, error) {
	var out threatReportingSubscriptionList
	if err := c.DoRead(ctx, http.MethodGet, threatReportingSubscriptions, nil, nil, &out); err != nil {
		return nil, err
	}
	sort.SliceStable(out.Value, func(i, j int) bool { return out.Value[i].SubscriptionID < out.Value[j].SubscriptionID })
	return out.Value, nil
}

func (c *Client) GetThreatReportingSubscription(ctx context.Context, id string) (ThreatReportingSubscription, error) {
	items, err := c.ListThreatReportingSubscriptions(ctx)
	if err != nil {
		return ThreatReportingSubscription{}, err
	}
	for _, item := range items {
		if item.SubscriptionID == id {
			return item, nil
		}
	}
	return ThreatReportingSubscription{}, legacyNotFound(http.MethodGet, threatReportingSubscriptions)
}

func (c *Client) UpdateThreatReportingSubscription(ctx context.Context, id, oldClientState, clientState string) (ThreatReportingSubscription, error) {
	request := threatReportingUpdateRequest{OldClientState: oldClientState, ClientState: clientState}
	var out ThreatReportingSubscription
	path := threatReportingSubscriptions + "/" + url.PathEscape(id)
	if err := c.Do(ctx, http.MethodPatch, path, nil, request, &out); err != nil {
		return ThreatReportingSubscription{}, err
	}
	if out.SubscriptionID == "" {
		out.SubscriptionID = id
	}
	return out, nil
}

func (c *Client) DeleteThreatReportingSubscription(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, threatReportingSubscriptions+"/"+url.PathEscape(id), nil, nil, nil)
}

func legacyNotFound(method, path string) error {
	return &APIError{StatusCode: http.StatusNotFound, Method: method, Path: path}
}

func legacyPolicyForWrite(in LegacyPolicyScope, includeWebConditions bool) LegacyPolicyScope {
	out := LegacyPolicyScope{
		Bidirectional: in.Bidirectional, Comment: in.Comment, Description: in.Description,
		Enabled: in.Enabled, Enforced: in.Enforced, From: legacyTargetForWrite(in.From),
		FromDate: in.FromDate, FromEternal: in.FromEternal, FromPart: in.FromPart,
		Override: in.Override, To: legacyTargetForWrite(in.To), ToDate: in.ToDate, ToEternal: in.ToEternal,
	}
	if in.Conditions != nil {
		out.Conditions = &LegacyPolicyConditions{SourceIPs: sortedStrings(in.Conditions.SourceIPs)}
		if includeWebConditions {
			out.Conditions.Hostnames = sortedStrings(in.Conditions.Hostnames)
			out.Conditions.SPFDomains = sortedStrings(in.Conditions.SPFDomains)
		}
		if len(out.Conditions.SourceIPs) == 0 && len(out.Conditions.Hostnames) == 0 && len(out.Conditions.SPFDomains) == 0 {
			out.Conditions = nil
		}
	}
	return out
}

func legacyTargetForWrite(in LegacyPolicyTarget) LegacyPolicyTarget {
	return LegacyPolicyTarget{
		Type: in.Type, GroupID: in.ResolvedGroupID(), EmailDomain: in.EmailDomain,
		EmailAddress: in.EmailAddress, Attribute: in.Attribute,
	}
}

func canonicalizeLegacyPolicy(policy *LegacyPolicyScope) {
	resolveLegacyReadTarget(&policy.From, policy.FromType, policy.FromValue)
	resolveLegacyReadTarget(&policy.To, policy.ToType, policy.ToValue)
	if policy.Conditions == nil {
		return
	}
	policy.Conditions.SourceIPs = sortedStrings(policy.Conditions.SourceIPs)
	policy.Conditions.Hostnames = sortedStrings(policy.Conditions.Hostnames)
	policy.Conditions.SPFDomains = sortedStrings(policy.Conditions.SPFDomains)
}

func resolveLegacyReadTarget(target *LegacyPolicyTarget, targetType, targetValue string) {
	if target.Type == "" {
		target.Type = targetType
	}
	if targetValue == "" {
		return
	}
	switch target.Type {
	case "profile_group":
		if target.Group == nil && target.GroupID == "" {
			target.GroupID = targetValue
		}
	case "email_domain":
		if target.EmailDomain == "" {
			target.EmailDomain = targetValue
		}
	case "individual_email_address":
		if target.EmailAddress == "" {
			target.EmailAddress = targetValue
		}
	}
}

func canonicalizeWebSecurityPolicy(policy *WebSecurityURLPolicy) {
	for i := range policy.Policies {
		canonicalizeLegacyPolicy(&policy.Policies[i].Policy)
	}
	sort.SliceStable(policy.Policies, func(i, j int) bool {
		if policy.Policies[i].ID != policy.Policies[j].ID {
			return policy.Policies[i].ID < policy.Policies[j].ID
		}
		return legacyPolicyIdentity(policy.Policies[i].Policy) < legacyPolicyIdentity(policy.Policies[j].Policy)
	})
	sort.SliceStable(policy.URLs, func(i, j int) bool {
		return webSecurityURLIdentity(policy.URLs[i]) < webSecurityURLIdentity(policy.URLs[j])
	})
}

func legacyPolicyIdentity(policy LegacyPolicyScope) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", policy.Description, policy.From.Type, policy.FromValue, policy.To.Type, policy.ToValue)
}

func webSecurityURLIdentity(action WebSecurityURLAction) string {
	return fmt.Sprintf("%s\x00%s\x00%s", action.Type, action.Value, action.Action)
}

func sortedStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
