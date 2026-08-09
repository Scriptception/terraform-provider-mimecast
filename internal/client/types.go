package client

import "encoding/json"

type PolicyTarget struct {
	Type         string           `json:"type,omitempty"`
	Group        *TargetGroup     `json:"group,omitempty"`
	GroupID      string           `json:"groupId,omitempty"`
	Domain       string           `json:"domain,omitempty"`
	EmailAddress string           `json:"emailAddress,omitempty"`
	Attribute    *TargetAttribute `json:"attribute,omitempty"`
}

type TargetGroup struct {
	ID string `json:"id,omitempty"`
}

func (t PolicyTarget) ResolvedGroupID() string {
	if t.Group != nil && t.Group.ID != "" {
		return t.Group.ID
	}
	return t.GroupID
}

type TargetAttribute struct {
	ID    string `json:"id,omitempty"`
	Value string `json:"value,omitempty"`
}

type Policy struct {
	ID            string       `json:"id,omitempty"`
	Description   string       `json:"description,omitempty"`
	Option        string       `json:"option,omitempty"`
	DefinitionID  string       `json:"definitionId,omitempty"`
	FromPart      string       `json:"fromPart,omitempty"`
	From          PolicyTarget `json:"from,omitempty"`
	To            PolicyTarget `json:"to,omitempty"`
	Enabled       *bool        `json:"enabled,omitempty"`
	Enforced      *bool        `json:"enforced,omitempty"`
	Override      *bool        `json:"override,omitempty"`
	Bidirectional *bool        `json:"bidirectional,omitempty"`
	FromEternal   *bool        `json:"fromEternal,omitempty"`
	ToEternal     *bool        `json:"toEternal,omitempty"`
	FromDateTime  string       `json:"fromDateTime,omitempty"`
	ToDateTime    string       `json:"toDateTime,omitempty"`
	FromDate      string       `json:"fromDate,omitempty"`
	ToDate        string       `json:"toDate,omitempty"`
	SourceIPs     []string     `json:"sourceIPs,omitempty"`
	Hostnames     []string     `json:"hostnames,omitempty"`
	SPFDomains    []string     `json:"spfDomains,omitempty"`
}

type DeliveryRouteDefinition struct {
	ID               string              `json:"id,omitempty"`
	Description      string              `json:"description,omitempty"`
	Hostname         string              `json:"hostname,omitempty"`
	Port             int64               `json:"port,omitempty"`
	AlternateRouteID string              `json:"alternateRouteId,omitempty"`
	SMTPAuth         *SMTPAuthentication `json:"smtpAuthentication,omitempty"`
	AuthMechanisms   []string            `json:"-"`
	Username         string              `json:"-"`
	Domain           string              `json:"-"`
}

type SMTPAuthentication struct {
	AuthMechanisms []string `json:"authMechanisms,omitempty"`
	Username       string   `json:"username,omitempty"`
	Password       string   `json:"password,omitempty"`
	Domain         string   `json:"domain,omitempty"`
}

type DNSOutboundDefinition struct {
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Selector    string `json:"selector,omitempty"`
	SignDKIM    *bool  `json:"signDkim,omitempty"`
	KeyLength   int64  `json:"keyLength,omitempty"`
	DNSAddress  string `json:"dnsAddress,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	Validated   *bool  `json:"validated,omitempty"`
}

type ManagedURL struct {
	ID                   string `json:"id,omitempty"`
	URL                  string `json:"url,omitempty"`
	Action               string `json:"action,omitempty"`
	MatchType            string `json:"matchType,omitempty"`
	Comment              string `json:"comment,omitempty"`
	DisableLogClick      *bool  `json:"disableLogClick,omitempty"`
	DisableRewrite       *bool  `json:"disableRewrite,omitempty"`
	DisableUserAwareness *bool  `json:"disableUserAwareness,omitempty"`
	Scheme               string `json:"-"`
	Domain               string `json:"-"`
	Port                 int64  `json:"-"`
	Path                 string `json:"-"`
	QueryString          string `json:"-"`
}

func (m *ManagedURL) UnmarshalJSON(data []byte) error {
	var response struct {
		ID                   string `json:"id"`
		URL                  string `json:"url"`
		Action               string `json:"action"`
		MatchType            string `json:"matchType"`
		Comment              string `json:"comment"`
		DisableLogClick      *bool  `json:"disableLogClick"`
		DisableRewrite       *bool  `json:"disableRewrite"`
		DisableUserAwareness *bool  `json:"disableUserAwareness"`
		Scheme               string `json:"scheme"`
		Domain               string `json:"domain"`
		Port                 int64  `json:"port"`
		Path                 string `json:"path"`
		QueryString          string `json:"queryString"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}
	*m = ManagedURL{
		ID:                   response.ID,
		URL:                  response.URL,
		Action:               response.Action,
		MatchType:            response.MatchType,
		Comment:              response.Comment,
		DisableLogClick:      response.DisableLogClick,
		DisableRewrite:       response.DisableRewrite,
		DisableUserAwareness: response.DisableUserAwareness,
		Scheme:               response.Scheme,
		Domain:               response.Domain,
		Port:                 response.Port,
		Path:                 response.Path,
		QueryString:          response.QueryString,
	}
	return nil
}

type LegacyEnvelope[T any] struct {
	Data []T `json:"data,omitempty"`
	Fail []struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	} `json:"fail,omitempty"`
	Meta struct {
		Pagination struct {
			PageSize  int    `json:"pageSize,omitempty"`
			PageToken string `json:"pageToken,omitempty"`
			Next      string `json:"next,omitempty"`
		} `json:"pagination,omitempty"`
	} `json:"meta,omitempty"`
}

type PageMeta struct {
	NextPage      string `json:"nextPage,omitempty"`
	NextPageToken string `json:"nextPageToken,omitempty"`
	Pagination    struct {
		Next          string `json:"next,omitempty"`
		NextPage      string `json:"nextPage,omitempty"`
		NextPageToken string `json:"nextPageToken,omitempty"`
	} `json:"pagination,omitempty"`
}

type IDResponse struct {
	ID string `json:"id"`
}

type IDResponsePolicy struct {
	ID       string `json:"id"`
	PolicyID string `json:"policyId"`
}

type RawMap map[string]any

func CopyRaw(v any) RawMap {
	b, _ := json.Marshal(v)
	out := RawMap{}
	_ = json.Unmarshal(b, &out)
	return out
}
