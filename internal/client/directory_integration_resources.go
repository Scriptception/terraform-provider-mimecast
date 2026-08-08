package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	activeDirectoryIntegrationPath = "/directory/cloud-gateway/v1/integrations/active-directory"
	googleDirectoryIntegrationPath = "/directory/cloud-gateway/v1/integrations/google"
	m365DirectoryIntegrationPath   = "/directory/cloud-gateway/v1/integrations/m365"
)

// UnlinkLimit accepts the string values used by create and update responses,
// and the integer values documented for read responses.
type UnlinkLimit string

func (u *UnlinkLimit) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*u = ""
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*u = UnlinkLimit(normalizeUnlinkLimit(text))
		return nil
	}

	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return fmt.Errorf("decode maxUnlink: %w", err)
	}
	if _, err := strconv.ParseInt(number.String(), 10, 64); err != nil {
		return fmt.Errorf("decode maxUnlink: %w", err)
	}
	*u = UnlinkLimit(normalizeUnlinkLimit(number.String()))
	return nil
}

func normalizeUnlinkLimit(value string) string {
	compact := strings.ReplaceAll(strings.TrimSpace(value), ",", "")
	switch compact {
	case "1000":
		return "1,000"
	case "2000":
		return "2,000"
	case "5000":
		return "5,000"
	case "10000":
		return "10,000"
	case "50000":
		return "50,000"
	case "100000":
		return "100,000"
	default:
		return compact
	}
}

type ActiveDirectoryIntegrationCreateRequest struct {
	Description                 string    `json:"description"`
	Info                        *string   `json:"info,omitempty"`
	Domains                     *[]string `json:"domains,omitempty"`
	Hostname                    string    `json:"hostname"`
	AlternateHostname           string    `json:"alternateHostname"`
	Port                        *int64    `json:"port,omitempty"`
	UserDN                      string    `json:"userDn"`
	Password                    string    `json:"password"`
	RootDN                      string    `json:"rootDn"`
	EncryptionMode              *string   `json:"encryptionMode,omitempty"`
	AcknowledgeDisabledAccounts *bool     `json:"acknowledgeDisabledAccounts,omitempty"`
	Enabled                     *bool     `json:"enabled,omitempty"`
	MaxUnlink                   *string   `json:"maxUnlink,omitempty"`
	SyncContacts                *bool     `json:"syncContacts,omitempty"`
	DeleteUsers                 *bool     `json:"deleteUsers,omitempty"`
}

type ActiveDirectoryIntegrationUpdateRequest struct {
	Description                 *string   `json:"description,omitempty"`
	Info                        *string   `json:"info,omitempty"`
	Domains                     *[]string `json:"domains,omitempty"`
	Hostname                    *string   `json:"hostname,omitempty"`
	AlternateHostname           *string   `json:"alternateHostname,omitempty"`
	Port                        *int64    `json:"port,omitempty"`
	UserDN                      *string   `json:"userDn,omitempty"`
	Password                    *string   `json:"password,omitempty"`
	RootDN                      *string   `json:"rootDn,omitempty"`
	EncryptionMode              *string   `json:"encryptionMode,omitempty"`
	AcknowledgeDisabledAccounts *bool     `json:"acknowledgeDisabledAccounts,omitempty"`
	Enabled                     *bool     `json:"enabled,omitempty"`
	MaxUnlink                   *string   `json:"maxUnlink,omitempty"`
	SyncContacts                *bool     `json:"syncContacts,omitempty"`
	DeleteUsers                 *bool     `json:"deleteUsers,omitempty"`
}

type ActiveDirectoryIntegration struct {
	ID                          string       `json:"-"`
	Enabled                     *bool        `json:"enabled,omitempty"`
	Description                 *string      `json:"description,omitempty"`
	Info                        *string      `json:"info,omitempty"`
	Hostname                    *string      `json:"hostname,omitempty"`
	AlternateHostname           *string      `json:"alternateHostname,omitempty"`
	Port                        *int64       `json:"port,omitempty"`
	UserDN                      *string      `json:"userDn,omitempty"`
	RootDN                      *string      `json:"rootDn,omitempty"`
	EncryptionMode              *string      `json:"encryptionMode,omitempty"`
	Status                      *string      `json:"status,omitempty"`
	LastSyncDateTime            *string      `json:"lastSyncDateTime,omitempty"`
	SyncRunning                 *bool        `json:"syncRunning,omitempty"`
	Domains                     *[]string    `json:"domains,omitempty"`
	AcknowledgeDisabledAccounts *bool        `json:"acknowledgeDisabledAccounts,omitempty"`
	MaxUnlink                   *UnlinkLimit `json:"maxUnlink,omitempty"`
	SyncContacts                *bool        `json:"syncContacts,omitempty"`
	DeleteUsers                 *bool        `json:"deleteUsers,omitempty"`
}

type GoogleDirectoryIntegrationCreateRequest struct {
	Enabled                     *bool     `json:"enabled,omitempty"`
	Description                 string    `json:"description"`
	Info                        *string   `json:"info,omitempty"`
	Domains                     *[]string `json:"domains,omitempty"`
	MaxUnlink                   *string   `json:"maxUnlink,omitempty"`
	DeleteUsers                 *bool     `json:"deleteUsers,omitempty"`
	AcknowledgeDisabledAccounts *bool     `json:"acknowledgeDisabledAccounts,omitempty"`
	User                        string    `json:"user"`
	Key                         string    `json:"key"`
}

type GoogleDirectoryIntegrationUpdateRequest struct {
	AcknowledgeDisabledAccounts *bool     `json:"acknowledgeDisabledAccounts,omitempty"`
	Enabled                     *bool     `json:"enabled,omitempty"`
	Description                 *string   `json:"description,omitempty"`
	Info                        *string   `json:"info,omitempty"`
	Domains                     *[]string `json:"domains,omitempty"`
	MaxUnlink                   *string   `json:"maxUnlink,omitempty"`
	DeleteUsers                 *bool     `json:"deleteUsers,omitempty"`
	User                        *string   `json:"user,omitempty"`
	Key                         *string   `json:"key,omitempty"`
}

type GoogleDirectoryIntegration struct {
	ID                          string       `json:"-"`
	Enabled                     *bool        `json:"enabled,omitempty"`
	Description                 *string      `json:"description,omitempty"`
	Info                        *string      `json:"info,omitempty"`
	User                        *string      `json:"user,omitempty"`
	LastSyncDateTime            *string      `json:"lastSyncDateTime,omitempty"`
	Status                      *string      `json:"status,omitempty"`
	SyncRunning                 *bool        `json:"syncRunning,omitempty"`
	Domains                     *[]string    `json:"domains,omitempty"`
	AcknowledgeDisabledAccounts *bool        `json:"acknowledgeDisabledAccounts,omitempty"`
	MaxUnlink                   *UnlinkLimit `json:"maxUnlink,omitempty"`
	DeleteUsers                 *bool        `json:"deleteUsers,omitempty"`
}

type Microsoft365DirectoryIntegrationCreateRequest struct {
	Description                 string    `json:"description"`
	Info                        *string   `json:"info,omitempty"`
	Domains                     *[]string `json:"domains,omitempty"`
	ConnectorID                 *string   `json:"connectorId,omitempty"`
	TenantDomain                string    `json:"tenantDomain"`
	ServerSubtype               *string   `json:"serverSubtype,omitempty"`
	SyncGuestUsers              *bool     `json:"syncGuestUsers,omitempty"`
	AcknowledgeDisabledAccounts *bool     `json:"acknowledgeDisabledAccounts,omitempty"`
	Enabled                     *bool     `json:"enabled,omitempty"`
	MaxUnlink                   *string   `json:"maxUnlink,omitempty"`
	SyncContacts                *bool     `json:"syncContacts,omitempty"`
	DeleteUsers                 *bool     `json:"deleteUsers,omitempty"`
}

type Microsoft365DirectoryIntegrationUpdateRequest struct {
	Description                 *string   `json:"description,omitempty"`
	Info                        *string   `json:"info,omitempty"`
	Domains                     *[]string `json:"domains,omitempty"`
	ConnectorID                 *string   `json:"connectorId,omitempty"`
	TenantDomain                *string   `json:"tenantDomain,omitempty"`
	ServerSubtype               *string   `json:"serverSubtype,omitempty"`
	SyncGuestUsers              *bool     `json:"syncGuestUsers,omitempty"`
	AcknowledgeDisabledAccounts *bool     `json:"acknowledgeDisabledAccounts,omitempty"`
	Enabled                     *bool     `json:"enabled,omitempty"`
	MaxUnlink                   *string   `json:"maxUnlink,omitempty"`
	SyncContacts                *bool     `json:"syncContacts,omitempty"`
	DeleteUsers                 *bool     `json:"deleteUsers,omitempty"`
}

type Microsoft365DirectoryIntegration struct {
	ID                          string       `json:"-"`
	Enabled                     *bool        `json:"enabled,omitempty"`
	Description                 *string      `json:"description,omitempty"`
	Info                        *string      `json:"info,omitempty"`
	ConnectorID                 *string      `json:"connectorId,omitempty"`
	ClientID                    *string      `json:"clientId,omitempty"`
	TenantDomain                *string      `json:"tenantDomain,omitempty"`
	ServerSubtype               *string      `json:"serverSubtype,omitempty"`
	SyncGuestUsers              *bool        `json:"syncGuestUsers,omitempty"`
	LastSyncDateTime            *string      `json:"lastSyncDateTime,omitempty"`
	SyncRunning                 *bool        `json:"syncRunning,omitempty"`
	Domains                     *[]string    `json:"domains,omitempty"`
	AcknowledgeDisabledAccounts *bool        `json:"acknowledgeDisabledAccounts,omitempty"`
	MaxUnlink                   *UnlinkLimit `json:"maxUnlink,omitempty"`
	SyncContacts                *bool        `json:"syncContacts,omitempty"`
	DeleteUsers                 *bool        `json:"deleteUsers,omitempty"`
}

func (c *Client) CreateActiveDirectoryIntegration(ctx context.Context, request ActiveDirectoryIntegrationCreateRequest) (string, error) {
	return c.createDirectoryIntegration(ctx, activeDirectoryIntegrationPath, request)
}

func (c *Client) GetActiveDirectoryIntegration(ctx context.Context, id string) (ActiveDirectoryIntegration, error) {
	var out ActiveDirectoryIntegration
	err := c.Do(ctx, http.MethodGet, directoryIntegrationObjectPath(activeDirectoryIntegrationPath, id), nil, nil, &out)
	out.ID = id
	return out, err
}

func (c *Client) UpdateActiveDirectoryIntegration(ctx context.Context, id string, request ActiveDirectoryIntegrationUpdateRequest) error {
	return c.Do(ctx, http.MethodPatch, directoryIntegrationObjectPath(activeDirectoryIntegrationPath, id), nil, request, nil)
}

func (c *Client) DeleteActiveDirectoryIntegration(ctx context.Context, id string) error {
	return c.deleteDirectoryIntegration(ctx, activeDirectoryIntegrationPath, id)
}

func (c *Client) CreateGoogleDirectoryIntegration(ctx context.Context, request GoogleDirectoryIntegrationCreateRequest) (string, error) {
	return c.createDirectoryIntegration(ctx, googleDirectoryIntegrationPath, request)
}

func (c *Client) GetGoogleDirectoryIntegration(ctx context.Context, id string) (GoogleDirectoryIntegration, error) {
	var out GoogleDirectoryIntegration
	err := c.Do(ctx, http.MethodGet, directoryIntegrationObjectPath(googleDirectoryIntegrationPath, id), nil, nil, &out)
	out.ID = id
	return out, err
}

func (c *Client) UpdateGoogleDirectoryIntegration(ctx context.Context, id string, request GoogleDirectoryIntegrationUpdateRequest) error {
	return c.Do(ctx, http.MethodPatch, directoryIntegrationObjectPath(googleDirectoryIntegrationPath, id), nil, request, nil)
}

func (c *Client) DeleteGoogleDirectoryIntegration(ctx context.Context, id string) error {
	return c.deleteDirectoryIntegration(ctx, googleDirectoryIntegrationPath, id)
}

func (c *Client) CreateMicrosoft365DirectoryIntegration(ctx context.Context, request Microsoft365DirectoryIntegrationCreateRequest) (string, error) {
	return c.createDirectoryIntegration(ctx, m365DirectoryIntegrationPath, request)
}

func (c *Client) GetMicrosoft365DirectoryIntegration(ctx context.Context, id string) (Microsoft365DirectoryIntegration, error) {
	var out Microsoft365DirectoryIntegration
	err := c.Do(ctx, http.MethodGet, directoryIntegrationObjectPath(m365DirectoryIntegrationPath, id), nil, nil, &out)
	out.ID = id
	return out, err
}

func (c *Client) UpdateMicrosoft365DirectoryIntegration(ctx context.Context, id string, request Microsoft365DirectoryIntegrationUpdateRequest) error {
	return c.Do(ctx, http.MethodPatch, directoryIntegrationObjectPath(m365DirectoryIntegrationPath, id), nil, request, nil)
}

func (c *Client) DeleteMicrosoft365DirectoryIntegration(ctx context.Context, id string) error {
	return c.deleteDirectoryIntegration(ctx, m365DirectoryIntegrationPath, id)
}

func (c *Client) createDirectoryIntegration(ctx context.Context, apiPath string, request any) (string, error) {
	var out IDResponse
	if err := c.Do(ctx, http.MethodPost, apiPath, nil, request, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("mimecast: create directory integration response did not include an ID")
	}
	return out.ID, nil
}

func (c *Client) deleteDirectoryIntegration(ctx context.Context, apiPath, id string) error {
	return c.Do(ctx, http.MethodDelete, directoryIntegrationObjectPath(apiPath, id), nil, nil, nil)
}

func directoryIntegrationObjectPath(apiPath, id string) string {
	return apiPath + "/" + url.PathEscape(id)
}
