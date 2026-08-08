package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

const journalingServicesPath = "/journaling/cloud-gateway/v1/services"

type JournalingServiceCreateRequest struct {
	Description                     string                          `json:"description"`
	Enabled                         *bool                           `json:"enabled,omitempty"`
	MessageFormat                   *string                         `json:"messageFormat,omitempty"`
	RemoveJournalHeaders            *bool                           `json:"removeJournalHeaders,omitempty"`
	JournalNonInternalAddresses     *bool                           `json:"journalNonInternalAddresses,omitempty"`
	JournalUnknownInternalAddresses *bool                           `json:"journalUnknownInternalAddresses,omitempty"`
	SMTPJournalingConnection        *SMTPJournalingConnectionCreate `json:"smtpJournalingConnection,omitempty"`
	POP3JournalingConnection        *POP3JournalingConnectionCreate `json:"pop3JournalingConnection,omitempty"`
}

type SMTPJournalingConnectionCreate struct {
	EmailAddress          string    `json:"emailAddress"`
	IPRanges              *[]string `json:"ipRanges,omitempty"`
	UsesAuthentication    *bool     `json:"usesAuthentication,omitempty"`
	Password              *string   `json:"password,omitempty"`
	UsesTLS               *bool     `json:"usesTls,omitempty"`
	PrefersClearText      *bool     `json:"prefersClearText,omitempty"`
	ExtendedDeduplication *bool     `json:"extendedDeduplication,omitempty"`
	DeliveryWaitAttempts  *int64    `json:"deliveryWaitAttempts,omitempty"`
	InactivityTimeout     *int64    `json:"inactivityTimeout,omitempty"`
	ProcessInitialDelay   *int64    `json:"processInitialDelay,omitempty"`
}

type POP3JournalingConnectionCreate struct {
	EmailAddress             string `json:"emailAddress"`
	Mailbox                  string `json:"mailbox"`
	Password                 string `json:"password"`
	Host                     string `json:"host"`
	Port                     *int64 `json:"port,omitempty"`
	UsesPOP3S                *bool  `json:"usesPOP3S,omitempty"`
	EncryptionIsRelaxed      *bool  `json:"encryptionIsRelaxed,omitempty"`
	DetailedLoggingIsEnabled *bool  `json:"detailedLoggingIsEnabled,omitempty"`
}

type JournalingServiceUpdateRequest struct {
	Description                     *string                         `json:"description,omitempty"`
	Enabled                         *bool                           `json:"enabled,omitempty"`
	MessageFormat                   *string                         `json:"messageFormat,omitempty"`
	RemoveJournalHeaders            *bool                           `json:"removeJournalHeaders,omitempty"`
	JournalNonInternalAddresses     *bool                           `json:"journalNonInternalAddresses,omitempty"`
	JournalUnknownInternalAddresses *bool                           `json:"journalUnknownInternalAddresses,omitempty"`
	TransferProtocol                *string                         `json:"transferProtocol,omitempty"`
	SMTPJournalingConnection        *SMTPJournalingConnectionUpdate `json:"smtpJournalingConnection,omitempty"`
	POP3JournalingConnection        *POP3JournalingConnectionUpdate `json:"pop3JournalingConnection,omitempty"`
}

type SMTPJournalingConnectionUpdate struct {
	EmailAddress          *string   `json:"emailAddress,omitempty"`
	IPRanges              *[]string `json:"ipRanges,omitempty"`
	UseAuthentication     *bool     `json:"useAuthentication,omitempty"`
	Password              *string   `json:"password,omitempty"`
	UseTLS                *bool     `json:"useTls,omitempty"`
	PreferClearText       *bool     `json:"preferClearText,omitempty"`
	ExtendedDeduplication *bool     `json:"extendedDeduplication,omitempty"`
	DeliveryWaitAttempts  *int64    `json:"deliveryWaitAttempts,omitempty"`
	InactivityTimeout     *int64    `json:"inactivityTimeout,omitempty"`
	ProcessInitialDelay   *int64    `json:"processInitialDelay,omitempty"`
}

type POP3JournalingConnectionUpdate struct {
	EmailAddress      *string `json:"emailAddress,omitempty"`
	Mailbox           *string `json:"mailbox,omitempty"`
	Password          *string `json:"password,omitempty"`
	Host              *string `json:"host,omitempty"`
	Port              *int64  `json:"port,omitempty"`
	UsePOP3           *bool   `json:"usePop3,omitempty"`
	RelaxedEncryption *bool   `json:"relaxedEncryption,omitempty"`
	DetailedLogging   *bool   `json:"detailedLogging,omitempty"`
}

// JournalingServiceRead deliberately has no password fields. Mimecast may
// return them in the documented response shape, but they must never reach
// Terraform state or diagnostics.
type JournalingServiceRead struct {
	ID                              *string                       `json:"id,omitempty"`
	Description                     *string                       `json:"description,omitempty"`
	MessageFormat                   *string                       `json:"messageFormat,omitempty"`
	QueueSize                       *int64                        `json:"queueSize,omitempty"`
	RemoveJournalHeaders            *bool                         `json:"removeJournalHeaders,omitempty"`
	TransferProtocol                *string                       `json:"transferProtocol,omitempty"`
	Enabled                         *bool                         `json:"enabled,omitempty"`
	JournalNonInternalAddresses     *bool                         `json:"journalNonInternalAddresses,omitempty"`
	JournalUnknownInternalAddresses *bool                         `json:"journalUnknownInternalAddresses,omitempty"`
	POP3JournalingConnection        *POP3JournalingConnectionRead `json:"pop3JournalingConnection,omitempty"`
	SMTPJournalingConnection        *SMTPJournalingConnectionRead `json:"smtpJournalingConnection,omitempty"`
	StatusInfo                      *JournalingServiceStatusInfo  `json:"statusInfo,omitempty"`
}

type SMTPJournalingConnectionRead struct {
	EmailAddress          *string   `json:"emailAddress,omitempty"`
	IPRanges              *[]string `json:"ipRanges,omitempty"`
	UsesAuthentication    *bool     `json:"usesAuthentication,omitempty"`
	UsesTLS               *bool     `json:"usesTls,omitempty"`
	PrefersClearText      *bool     `json:"prefersClearText,omitempty"`
	ExtendedDeduplication *bool     `json:"extendedDeduplication,omitempty"`
	DeliveryWaitAttempts  *int64    `json:"deliveryWaitAttempts,omitempty"`
	InactivityTimeout     *int64    `json:"inactivityTimeout,omitempty"`
	ProcessInitialDelay   *int64    `json:"processInitialDelay,omitempty"`
	Hostnames             *[]string `json:"hostnames,omitempty"`
}

type POP3JournalingConnectionRead struct {
	EmailAddress             *string `json:"emailAddress,omitempty"`
	Mailbox                  *string `json:"mailbox,omitempty"`
	Host                     *string `json:"host,omitempty"`
	Port                     *int64  `json:"port,omitempty"`
	UsesPOP3S                *bool   `json:"usesPOP3S,omitempty"`
	EncryptionIsRelaxed      *bool   `json:"encryptionIsRelaxed,omitempty"`
	DetailedLoggingIsEnabled *bool   `json:"detailedLoggingIsEnabled,omitempty"`
}

type JournalingServiceStatusInfo struct {
	LastReceivedDateTime *string `json:"lastReceivedDateTime,omitempty"`
	Status               *string `json:"status,omitempty"`
}

func (c *Client) CreateJournalingServiceResource(ctx context.Context, request JournalingServiceCreateRequest) (string, error) {
	var out IDResponse
	if err := c.Do(ctx, http.MethodPost, journalingServicesPath, nil, request, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("mimecast: create journaling service response did not include an ID")
	}
	return out.ID, nil
}

func (c *Client) GetJournalingServiceResource(ctx context.Context, id string) (JournalingServiceRead, error) {
	var out JournalingServiceRead
	err := c.Do(ctx, http.MethodGet, journalingServiceObjectPath(id), nil, nil, &out)
	if out.ID == nil {
		out.ID = &id
	}
	return out, err
}

func (c *Client) UpdateJournalingServiceResource(ctx context.Context, id string, request JournalingServiceUpdateRequest) error {
	return c.Do(ctx, http.MethodPatch, journalingServiceObjectPath(id), nil, request, nil)
}

func (c *Client) DeleteJournalingServiceResource(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, journalingServiceObjectPath(id), nil, nil, nil)
}

func journalingServiceObjectPath(id string) string {
	return journalingServicesPath + "/" + url.PathEscape(id)
}
