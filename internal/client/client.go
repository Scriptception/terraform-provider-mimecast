// Package client implements a small Mimecast API 2.0 client for Terraform resources.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBaseURL  = "https://api.services.mimecast.com"
	DefaultTokenURL = "https://api.services.mimecast.com/oauth/token"
	defaultTimeout  = 30 * time.Second
	defaultPageSize = 100
	defaultRetries  = 4
	maxResponseSize = 10 << 20
	maxRetryDelay   = 5 * time.Minute
)

// Config holds Mimecast client configuration.
type Config struct {
	BaseURL         string
	TokenURL        string
	ClientID        string
	ClientSecret    string
	TokenAuthMethod string
	Scopes          []string
	Insecure        bool
	UserAgent       string
	Timeout         time.Duration
	MaxRetries      int
	PageSize        int
	ReadOnly        bool
	ProxyURL        string
}

// Client talks to Mimecast APIs.
type Client struct {
	baseURL         *url.URL
	tokenURL        string
	clientID        string
	clientSecret    string
	tokenAuthMethod string
	scopes          []string
	httpClient      *http.Client
	userAgent       string
	maxRetries      int
	pageSize        int
	readOnly        bool

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

type serviceTransport struct {
	base               http.RoundTripper
	allowedHTTPOrigins map[string]struct{}
}

func (t serviceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme == "https" {
		return t.base.RoundTrip(request)
	}
	origin, valid := loopbackHTTPOrigin(request.URL)
	if _, allowed := t.allowedHTTPOrigins[origin]; !valid || !allowed {
		return nil, errors.New("mimecast: blocked non-HTTPS request outside configured loopback service origins")
	}
	return t.base.RoundTrip(request)
}

// ReadOnlyError is returned before a mutating request is built or sent when
// the provider's fail-closed read-only mode is enabled.
type ReadOnlyError struct {
	Method string
	Path   string
}

func (e *ReadOnlyError) Error() string {
	return fmt.Sprintf("mimecast: %s %s blocked because provider read_only is enabled", e.Method, e.Path)
}

// ResponseTooLargeError reports a response that exceeded the fixed safety cap.
// It deliberately contains no response content.
type ResponseTooLargeError struct {
	Method string
	Path   string
	Limit  int64
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("mimecast: %s %s response exceeded %d bytes", e.Method, e.Path, e.Limit)
}

// APIError is returned for non-2xx API responses. Bodies are summarized to avoid leaking tenant data.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return fmt.Sprintf("mimecast: %s %s returned %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("mimecast: %s %s returned %d: %s", e.Method, e.Path, e.StatusCode, msg)
}

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// New returns a configured client.
func New(cfg Config) (*Client, error) {
	base := firstNonEmpty(cfg.BaseURL, DefaultBaseURL)
	u, err := parseServiceURL(strings.TrimRight(base, "/"), "base_url")
	if err != nil {
		return nil, err
	}
	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = strings.TrimRight(base, "/") + "/oauth/token"
	}
	tokenEndpoint, err := parseServiceURL(tokenURL, "token_url")
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, errors.New("mimecast: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("mimecast: client_secret is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	retries := cfg.MaxRetries
	if retries < 0 {
		retries = defaultRetries
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > defaultPageSize {
		pageSize = defaultPageSize
	}
	authMethod := firstNonEmpty(cfg.TokenAuthMethod, "client_secret_post")
	if authMethod != "client_secret_post" && authMethod != "client_secret_basic" {
		return nil, fmt.Errorf("mimecast: token_auth_method must be client_secret_post or client_secret_basic")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	var proxyURL *url.URL
	if strings.TrimSpace(cfg.ProxyURL) != "" {
		proxyURL, err = url.Parse(strings.TrimSpace(cfg.ProxyURL))
		if err != nil || proxyURL.Host == "" || proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
			return nil, fmt.Errorf("mimecast: proxy_url must include a valid scheme and host")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	allowedHTTPOrigins := make(map[string]struct{}, 2)
	for _, endpoint := range []*url.URL{u, tokenEndpoint} {
		if origin, ok := loopbackHTTPOrigin(endpoint); ok {
			allowedHTTPOrigins[origin] = struct{}{}
		}
	}
	if len(allowedHTTPOrigins) > 0 && proxyURL != nil && !isLoopbackHost(proxyURL.Hostname()) {
		return nil, errors.New("mimecast: loopback HTTP service endpoints cannot use a non-loopback proxy")
	}
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit provider opt-in
	}
	ua := firstNonEmpty(cfg.UserAgent, "terraform-provider-mimecast")
	return &Client{
		baseURL: u, tokenURL: tokenURL, clientID: cfg.ClientID, clientSecret: cfg.ClientSecret, tokenAuthMethod: authMethod,
		scopes: cfg.Scopes, httpClient: &http.Client{Timeout: timeout, Transport: serviceTransport{base: transport, allowedHTTPOrigins: allowedHTTPOrigins}}, userAgent: ua, maxRetries: retries, pageSize: pageSize,
		readOnly: cfg.ReadOnly,
	}, nil
}

// IsAllowedServiceURL reports whether a Mimecast API or OAuth endpoint uses
// HTTPS, or HTTP on a numeric loopback address for local tests.
func IsAllowedServiceURL(value string) bool {
	_, err := parseServiceURL(value, "service URL")
	return err == nil
}

func parseServiceURL(value, name string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("mimecast: %s must be an absolute HTTPS URL; HTTP is allowed only on numeric loopback addresses for testing", name)
	}
	switch parsed.Scheme {
	case "https":
		return parsed, nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return parsed, nil
		}
	}
	return nil, fmt.Errorf("mimecast: %s must be an absolute HTTPS URL; HTTP is allowed only on numeric loopback addresses for testing", name)
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loopbackHTTPOrigin(parsed *url.URL) (string, bool) {
	if parsed == nil || parsed.Scheme != "http" {
		return "", false
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
	}
	return "http://" + net.JoinHostPort(ip.String(), port), true
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *Client) bearerToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.accessToken, nil
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(c.scopes) > 0 {
		form.Set("scope", strings.Join(c.scopes, " "))
	}
	if c.tokenAuthMethod == "client_secret_post" {
		form.Set("client_id", c.clientID)
		form.Set("client_secret", c.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("mimecast: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.tokenAuthMethod == "client_secret_basic" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mimecast: request oauth token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readLimitedBody(resp.Body, http.MethodPost, "/oauth/token")
	if err != nil {
		return "", fmt.Errorf("mimecast: read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &APIError{StatusCode: resp.StatusCode, Method: http.MethodPost, Path: "/oauth/token", Message: parseErrorMessage(body)}
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("mimecast: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("mimecast: token response did not include access_token")
	}
	expires := tr.ExpiresIn
	if expires <= 0 {
		expires = 300
	}
	c.accessToken = tr.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(expires) * time.Second)
	return c.accessToken, nil
}

// Do sends a JSON API request and decodes the JSON response into out when
// provided. Only GET, HEAD, and OPTIONS are treated as retry-safe reads.
func (c *Client) Do(ctx context.Context, method, apiPath string, query url.Values, body any, out any) error {
	return c.do(ctx, method, apiPath, query, body, out, isReadMethod(method))
}

// DoRead sends an explicitly side-effect-free read request. It exists for the
// small number of legacy Mimecast list operations that use POST. Callers must
// not use it for creates, updates, deletes, consent operations, or actions.
func (c *Client) DoRead(ctx context.Context, method, apiPath string, query url.Values, body any, out any) error {
	if method == http.MethodPost {
		if _, allowed := legacyPOSTReadPaths[apiPath]; !allowed {
			return fmt.Errorf("mimecast: POST %s is not an allowlisted legacy read operation", apiPath)
		}
	} else if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		return fmt.Errorf("mimecast: %s %s is not a supported read method", method, apiPath)
	}
	return c.do(ctx, method, apiPath, query, body, out, true)
}

var legacyPOSTReadPaths = map[string]struct{}{
	"/api/account/get-account":                                  {},
	"/api/policy/address-alteration/get-address-alteration-set": {},
	"/api/policy/address-alteration/get-definition":             {},
	"/api/policy/address-alteration/get-policy":                 {},
	"/api/policy/webwhiteurl/get-policy-with-targets":           {},
	"/api/provisioning/get-packages":                            {},
	"/api/ttp/url/get-all-managed-urls":                         {},
}

func (c *Client) do(ctx context.Context, method, apiPath string, query url.Values, body any, out any, safeRead bool) error {
	if c.readOnly && !safeRead {
		return &ReadOnlyError{Method: method, Path: apiPath}
	}
	for attempt := 0; ; attempt++ {
		err := c.doOnce(ctx, method, apiPath, query, body, out)
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if safeRead && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.clearToken()
			continue
		}
		if !safeRead || !errors.As(err, &apiErr) || !retryable(apiErr.StatusCode) || attempt >= c.maxRetries {
			return err
		}
		sleep := apiErr.RetryAfter
		if sleep <= 0 {
			sleep = time.Duration(250*(1<<attempt)) * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

func (c *Client) clearToken() {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.accessToken = ""
	c.tokenExpiry = time.Time{}
}

func (c *Client) doOnce(ctx context.Context, method, apiPath string, query url.Values, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mimecast: marshal request for %s: %w", apiPath, err)
		}
		reqBody = bytes.NewReader(b)
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(apiPath, "/")
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("mimecast: build request for %s: %w", apiPath, err)
	}
	token, err := c.bearerToken(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mimecast: %s %s: %w", method, apiPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := readLimitedBody(resp.Body, method, apiPath)
	if err != nil {
		return fmt.Errorf("mimecast: read response for %s: %w", apiPath, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Method: method, Path: apiPath, Message: parseErrorMessage(respBody), RetryAfter: parseRateLimitDelay(resp.Header)}
	}
	if msg := parseLegacyFailMessage(respBody); msg != "" {
		return &APIError{StatusCode: resp.StatusCode, Method: method, Path: apiPath, Message: msg}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("mimecast: decode response for %s: %w", apiPath, err)
		}
	}
	return nil
}

func parseLegacyFailMessage(body []byte) string {
	var env struct {
		Fail []struct {
			Errors []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Field   string `json:"field"`
			} `json:"errors"`
		} `json:"fail"`
	}
	if len(body) == 0 || json.Unmarshal(body, &env) != nil || len(env.Fail) == 0 {
		return ""
	}
	for _, f := range env.Fail {
		if len(f.Errors) > 0 {
			return safeCodeAndField(f.Errors[0].Code, f.Errors[0].Field)
		}
	}
	return "Mimecast returned one or more failed items"
}

// DoAllPages fetches cursor-paginated list endpoints and calls appendPage for each response.
func (c *Client) DoAllPages(ctx context.Context, apiPath string, query url.Values, pageOut func() any, appendPage func(any) error) error {
	pageQuery := url.Values{}
	for key, vals := range query {
		pageQuery[key] = append([]string(nil), vals...)
	}
	if pageQuery.Get("pageSize") == "" {
		pageQuery.Set("pageSize", strconv.Itoa(c.pageSize))
	}
	seen := map[string]struct{}{}
	for {
		out := pageOut()
		if err := c.DoRead(ctx, http.MethodGet, apiPath, pageQuery, nil, out); err != nil {
			return err
		}
		if err := appendPage(out); err != nil {
			return err
		}
		next := nextPageToken(out)
		if next == "" {
			return nil
		}
		if _, ok := seen[next]; ok {
			return fmt.Errorf("mimecast: pagination for %s repeated a page token", apiPath)
		}
		seen[next] = struct{}{}
		pageQuery.Set("pageToken", next)
	}
}

func parseErrorMessage(body []byte) string {
	var env struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Errors      []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Field   string `json:"field"`
		} `json:"errors"`
		Fail []struct {
			Errors []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		} `json:"fail"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "request rejected by Mimecast"
	}
	if env.Description != "" {
		return safeCodeAndField(env.Error, "")
	}
	if env.Error != "" {
		return safeCodeAndField(env.Error, "")
	}
	if len(env.Errors) > 0 {
		return safeCodeAndField(env.Errors[0].Code, env.Errors[0].Field)
	}
	if len(env.Fail) > 0 && len(env.Fail[0].Errors) > 0 {
		return safeCodeAndField(env.Fail[0].Errors[0].Code, "")
	}
	return "request rejected by Mimecast"
}

func safeCodeAndField(code, field string) string {
	code = safeIdentifier(code)
	field = safeIdentifier(field)
	switch {
	case code != "" && field != "":
		return "Mimecast error " + code + " for field " + field
	case code != "":
		return "Mimecast error " + code
	case field != "":
		return "Mimecast rejected field " + field
	default:
		return "request rejected by Mimecast"
	}
}

func safeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 80 {
		value = value[:80]
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-.[ ]", r) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

func parseRateLimitDelay(header http.Header) time.Duration {
	if delay := parseRetryAfter(header.Get("Retry-After")); delay > 0 {
		return boundedRetryDelay(delay)
	}
	for _, name := range []string{"X-RateLimit-Reset", "X-Mimecast-RateLimit-Reset"} {
		value := strings.TrimSpace(header.Get(name))
		if value == "" {
			continue
		}
		milliseconds, err := strconv.ParseInt(value, 10, 64)
		if err == nil && milliseconds >= 0 {
			return boundedRetryDelay(time.Duration(milliseconds) * time.Millisecond)
		}
	}
	return 0
}

func boundedRetryDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status >= 500
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func readLimitedBody(body io.Reader, method, apiPath string) ([]byte, error) {
	limited := io.LimitReader(body, maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("mimecast: read response for %s: %w", apiPath, err)
	}
	if len(data) > maxResponseSize {
		return nil, &ResponseTooLargeError{Method: method, Path: apiPath, Limit: maxResponseSize}
	}
	return data, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func nextPageToken(v any) string {
	b, _ := json.Marshal(v)
	var meta struct {
		Meta struct {
			NextPage   string `json:"nextPage"`
			PageToken  string `json:"nextPageToken"`
			Pagination struct {
				Next          string `json:"next"`
				NextPage      string `json:"nextPage"`
				NextPageToken string `json:"nextPageToken"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	_ = json.Unmarshal(b, &meta)
	if meta.Meta.NextPage != "" {
		return meta.Meta.NextPage
	}
	if meta.Meta.PageToken != "" {
		return meta.Meta.PageToken
	}
	if meta.Meta.Pagination.NextPageToken != "" {
		return meta.Meta.Pagination.NextPageToken
	}
	if meta.Meta.Pagination.NextPage != "" {
		return meta.Meta.Pagination.NextPage
	}
	return meta.Meta.Pagination.Next
}
