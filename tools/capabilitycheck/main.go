// Command capabilitycheck validates the checked Mimecast API 2.0 capability
// ledger and compares it with the current public developer portal.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	catalogueURL = "https://developer.services.mimecast.com/portals/api/sites/mimecast-prod-apigee-developer/liveportal/apis"
	specURL      = catalogueURL + "/%s/spec"
	userAgent    = "terraform-provider-mimecast-capability-check/0.2.1"
)

var surfacePattern = regexp.MustCompile(`^(resource|data_source)\.mimecast_[a-z0-9_]+$`)

type manifest struct {
	SchemaVersion int         `json:"schema_version"`
	API           apiMetadata `json:"api"`
	Operations    []operation `json:"operations"`
}

type apiMetadata struct {
	Version               string    `json:"version"`
	CatalogueURL          string    `json:"catalogue_url"`
	CheckedOn             string    `json:"checked_on"`
	ProductCount          int       `json:"product_count"`
	ProductOperationCount int       `json:"product_operation_count"`
	UniqueOperationCount  int       `json:"unique_operation_count"`
	OperationSetSHA256    string    `json:"operation_set_sha256"`
	Products              []product `json:"products"`
}

type product struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type operation struct {
	Method             string       `json:"method"`
	Path               string       `json:"path"`
	Products           []string     `json:"products"`
	Category           string       `json:"category"`
	Pagination         string       `json:"pagination"`
	Permission         permission   `json:"permission"`
	Disposition        string       `json:"disposition"`
	TerraformSurfaces  []string     `json:"terraform_surfaces,omitempty"`
	Reason             string       `json:"reason"`
	DeferReason        *deferReason `json:"defer_reason,omitempty"`
	ContractStatus     string       `json:"contract_status,omitempty"`
	TestStatus         string       `json:"test_status,omitempty"`
	ReleaseBlockingGap bool         `json:"release_blocking_gap"`
}

type permission struct {
	APIProducts               []string `json:"api_products"`
	DocumentedRolePermissions []string `json:"documented_role_permissions"`
	Source                    string   `json:"source"`
}

type deferReason struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type catalogueEnvelope struct {
	Data struct {
		APIDocs []struct {
			APIID string `json:"apiId"`
			Title string `json:"title"`
		} `json:"apiDocs"`
	} `json:"data"`
}

type specEnvelope struct {
	Data string `json:"data"`
}
type openAPISpec struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}
type liveCatalogue struct {
	Products              []product
	ProductOperationCount int
	Operations            []liveOperation
}
type liveOperation struct {
	Method, Path string
	Products     []string
}

func main() {
	manifestPath := flag.String("manifest", "../capabilities/api-v2.json", "capability manifest path")
	docPath := flag.String("doc", "../docs/api-coverage.md", "coverage document path")
	gapDocPath := flag.String("gap-doc", "../docs/api-gaps.md", "release-blocking gap report path")
	providerRoot := flag.String("provider-root", "..", "provider repository root")
	offline := flag.Bool("offline", false, "validate without contacting the Mimecast developer portal")
	refresh := flag.Bool("refresh", false, "refresh operation metadata and mark new operations unclassified")
	writeDoc := flag.Bool("write-doc", false, "write the generated coverage document")
	writeGapDoc := flag.Bool("write-gap-doc", false, "write the generated gap report")
	releaseCheck := flag.Bool("release", false, "fail if declarative coverage gaps remain")
	flag.Parse()

	current, err := readManifest(*manifestPath)
	if err != nil && !(*refresh && errors.Is(err, os.ErrNotExist)) {
		fatal(err)
	}
	if *refresh {
		live, err := fetchCatalogue()
		if err != nil {
			fatal(err)
		}
		current = refreshManifest(current, live)
		if err := writeJSON(*manifestPath, current); err != nil {
			fatal(err)
		}
	}
	if err := validateManifest(current); err != nil {
		fatal(err)
	}
	if err := validateSurfaceEvidence(current, *providerRoot); err != nil {
		fatal(err)
	}
	if !*offline && !*refresh {
		live, err := fetchCatalogue()
		if err != nil {
			fatal(err)
		}
		if err := compareLive(current, live); err != nil {
			fatal(err)
		}
	}
	if *writeDoc {
		mustWrite(*docPath, renderCoverage(current))
	}
	if *writeGapDoc {
		mustWrite(*gapDocPath, renderGaps(current))
	}
	if *releaseCheck && len(blockingGaps(current)) > 0 {
		fatal(fmt.Errorf("%d declarative operations lack an implemented typed surface; see %s", len(blockingGaps(current)), *gapDocPath))
	}
	fmt.Printf("capability manifest valid: %d unique operations, %d products, %d release-blocking gaps\n", len(current.Operations), len(current.API.Products), len(blockingGaps(current)))
}

func readManifest(path string) (manifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, err
	}
	var result manifest
	if err := json.Unmarshal(content, &result); err != nil {
		return manifest{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return result, nil
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o644)
}

func mustWrite(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fatal(err)
	}
}

func validateManifest(value manifest) error {
	categories := set("account_metadata", "configuration_discovery", "declarative_configuration", "identity_discovery", "integration_workflow", "operational_action", "operational_data", "security_telemetry", "verification_workflow")
	pagination := set("cursor", "request_body_cursor", "not_paginated")
	testStatuses := set("synthetic_contract", "synthetic_lifecycle", "live_read_only", "live_mutation")
	nonBlockingConfigurationDeferrals := set("no_safe_delete_contract", "no_safe_read_contract", "secret_not_readable_or_state_safe", "workflow_not_desired_state")
	var problems []string
	if value.SchemaVersion != 1 || value.API.Version != "2.0" {
		problems = append(problems, "schema_version must be 1 and api.version must be 2.0")
	}
	if value.API.CatalogueURL != catalogueURL {
		problems = append(problems, "api.catalogue_url is not the official catalogue URL")
	}
	if _, err := time.Parse("2006-01-02", value.API.CheckedOn); err != nil {
		problems = append(problems, "api.checked_on must use YYYY-MM-DD")
	}
	if value.API.ProductCount != len(value.API.Products) || value.API.UniqueOperationCount != len(value.Operations) {
		problems = append(problems, "checked counts do not match manifest arrays")
	}
	products := map[string]struct{}{}
	for _, item := range value.API.Products {
		if item.ID == "" || item.Title == "" {
			problems = append(problems, "product has empty id or title")
		}
		if _, exists := products[item.ID]; exists {
			problems = append(problems, "duplicate product "+item.ID)
		}
		products[item.ID] = struct{}{}
	}
	seen, previous := map[string]struct{}{}, ""
	for _, item := range value.Operations {
		key := operationKey(item.Method, item.Path)
		if _, exists := seen[key]; exists {
			problems = append(problems, "duplicate operation "+key)
		}
		seen[key] = struct{}{}
		if item.Method != strings.ToUpper(item.Method) || !strings.HasPrefix(item.Path, "/") || (previous != "" && key < previous) {
			problems = append(problems, "invalid or unsorted operation "+key)
		}
		previous = key
		if len(item.Products) == 0 || strings.Join(item.Products, ",") != strings.Join(item.Permission.APIProducts, ",") {
			problems = append(problems, key+" product and permission product sets must match")
		}
		for _, id := range item.Products {
			if _, exists := products[id]; !exists {
				problems = append(problems, key+" references unknown product "+id)
			}
		}
		if _, valid := categories[item.Category]; !valid {
			problems = append(problems, key+" has an unknown category")
		}
		if _, valid := pagination[item.Pagination]; !valid {
			problems = append(problems, key+" has an unknown pagination style")
		}
		if item.Permission.Source != "official_contract" && item.Permission.Source != "api_product_only" {
			problems = append(problems, key+" has an unknown permission source")
		}
		if item.Permission.Source == "official_contract" && len(item.Permission.DocumentedRolePermissions) == 0 {
			problems = append(problems, key+" says official_contract without a documented role permission")
		}
		if strings.TrimSpace(item.Reason) == "" {
			problems = append(problems, key+" has no classification reason")
		}
		switch item.Disposition {
		case "terraform":
			if len(item.TerraformSurfaces) == 0 || item.DeferReason != nil || item.ReleaseBlockingGap {
				problems = append(problems, key+" has inconsistent Terraform classification")
			}
			if item.ContractStatus != "official_contract_checked" {
				problems = append(problems, key+" has no verified contract status")
			}
			if _, valid := testStatuses[item.TestStatus]; !valid {
				problems = append(problems, key+" has no completed test status")
			}
			for _, surface := range item.TerraformSurfaces {
				if !surfacePattern.MatchString(surface) {
					problems = append(problems, key+" has invalid surface "+surface)
				}
			}
		case "excluded":
			if len(item.TerraformSurfaces) != 0 || item.DeferReason == nil || item.ContractStatus != "" || item.TestStatus != "" {
				problems = append(problems, key+" has inconsistent exclusion fields")
				break
			}
			if item.DeferReason.Code == "" || len(strings.TrimSpace(item.DeferReason.Detail)) < 24 || item.DeferReason.Code == "not_implemented" || item.DeferReason.Code == "generic_exclusion" {
				problems = append(problems, key+" lacks a stable, specific defer_reason")
			}
			configLike := item.Category == "declarative_configuration" || item.Category == "configuration_discovery"
			_, hasSpecificLimitation := nonBlockingConfigurationDeferrals[item.DeferReason.Code]
			if configLike && !item.ReleaseBlockingGap && !hasSpecificLimitation {
				problems = append(problems, key+" hides a declarative gap without an approved lifecycle or API limitation")
			}
		default:
			problems = append(problems, key+" is unknown or unclassified")
		}
	}
	if digest := operationSetDigest(value.Operations); value.API.OperationSetSHA256 != digest {
		problems = append(problems, "api.operation_set_sha256 does not match operations")
	}
	if len(problems) > 0 {
		return fmt.Errorf("manifest validation failed:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}

func validateSurfaceEvidence(value manifest, root string) error {
	var problems []string
	seen := map[string]struct{}{}
	for _, item := range value.Operations {
		for _, surface := range item.TerraformSurfaces {
			if _, done := seen[surface]; done {
				continue
			}
			seen[surface] = struct{}{}
			parts := strings.SplitN(surface, ".mimecast_", 2)
			kind, name := parts[0], parts[1]
			docKind := map[string]string{"resource": "resources", "data_source": "data-sources"}[kind]
			if _, err := os.Stat(filepath.Join(root, "docs", docKind, name+".md")); err != nil {
				problems = append(problems, surface+" has no generated documentation")
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("Terraform surface evidence failed:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}

func fetchCatalogue() (liveCatalogue, error) {
	client := &http.Client{Timeout: 45 * time.Second}
	var envelope catalogueEnvelope
	if err := getJSON(client, catalogueURL, &envelope); err != nil {
		return liveCatalogue{}, err
	}
	result, byKey := liveCatalogue{}, map[string]*liveOperation{}
	for _, api := range envelope.Data.APIDocs {
		result.Products = append(result.Products, product{ID: api.APIID, Title: api.Title})
		var wrapped specEnvelope
		if err := getJSON(client, fmt.Sprintf(specURL, api.APIID), &wrapped); err != nil {
			return liveCatalogue{}, err
		}
		var spec openAPISpec
		if err := json.Unmarshal([]byte(wrapped.Data), &spec); err != nil {
			return liveCatalogue{}, fmt.Errorf("decode %s spec: %w", api.APIID, err)
		}
		for path, methods := range spec.Paths {
			for method := range methods {
				method = strings.ToUpper(method)
				if !isHTTPMethod(method) {
					continue
				}
				result.ProductOperationCount++
				key := operationKey(method, path)
				if byKey[key] == nil {
					byKey[key] = &liveOperation{Method: method, Path: path}
				}
				byKey[key].Products = appendUnique(byKey[key].Products, api.APIID)
			}
		}
	}
	for _, item := range byKey {
		sort.Strings(item.Products)
		result.Operations = append(result.Operations, *item)
	}
	sort.Slice(result.Products, func(i, j int) bool { return result.Products[i].ID < result.Products[j].ID })
	sort.Slice(result.Operations, func(i, j int) bool {
		return operationKey(result.Operations[i].Method, result.Operations[i].Path) < operationKey(result.Operations[j].Method, result.Operations[j].Path)
	})
	return result, nil
}

func getJSON(client *http.Client, url string, out any) error {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("GET %s returned %d: %s", url, response.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(out)
}

func compareLive(value manifest, live liveCatalogue) error {
	checkedProducts, liveProducts := map[string]string{}, map[string]string{}
	for _, item := range value.API.Products {
		checkedProducts[item.ID] = item.Title
	}
	for _, item := range live.Products {
		liveProducts[item.ID] = item.Title
	}
	var problems []string
	for id, title := range liveProducts {
		if old, ok := checkedProducts[id]; !ok {
			problems = append(problems, "new API product "+id)
		} else if old != title {
			problems = append(problems, "renamed API product "+id)
		}
	}
	for id := range checkedProducts {
		if _, ok := liveProducts[id]; !ok {
			problems = append(problems, "removed API product "+id)
		}
	}
	checkedOps, liveOps := map[string]operation{}, map[string]liveOperation{}
	for _, item := range value.Operations {
		checkedOps[operationKey(item.Method, item.Path)] = item
	}
	for _, item := range live.Operations {
		liveOps[operationKey(item.Method, item.Path)] = item
	}
	for key, item := range liveOps {
		old, ok := checkedOps[key]
		if !ok {
			problems = append(problems, "new unclassified operation "+key)
		} else if strings.Join(old.Products, ",") != strings.Join(item.Products, ",") {
			problems = append(problems, key+" product membership changed")
		}
	}
	for key := range checkedOps {
		if _, ok := liveOps[key]; !ok {
			problems = append(problems, "removed operation remains classified "+key)
		}
	}
	if live.ProductOperationCount != value.API.ProductOperationCount {
		problems = append(problems, fmt.Sprintf("product operation count changed from %d to %d", value.API.ProductOperationCount, live.ProductOperationCount))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("live catalogue differs from manifest:\n- %s\nrun make capability-refresh and explicitly review every new operation", strings.Join(problems, "\n- "))
	}
	return nil
}

func refreshManifest(previous manifest, live liveCatalogue) manifest {
	existing := map[string]operation{}
	for _, item := range previous.Operations {
		existing[operationKey(item.Method, item.Path)] = item
	}
	result := manifest{SchemaVersion: 1, API: apiMetadata{Version: "2.0", CatalogueURL: catalogueURL, CheckedOn: time.Now().UTC().Format("2006-01-02"), ProductCount: len(live.Products), ProductOperationCount: live.ProductOperationCount, UniqueOperationCount: len(live.Operations), Products: live.Products}}
	for _, item := range live.Operations {
		key := operationKey(item.Method, item.Path)
		if old, ok := existing[key]; ok {
			old.Products, old.Permission.APIProducts = item.Products, item.Products
			result.Operations = append(result.Operations, old)
			continue
		}
		result.Operations = append(result.Operations, operation{Method: item.Method, Path: item.Path, Products: item.Products, Permission: permission{APIProducts: item.Products}, Disposition: "unclassified", Reason: "Needs explicit review."})
	}
	result.API.OperationSetSHA256 = operationSetDigest(result.Operations)
	return result
}

func renderCoverage(value manifest) string {
	type count struct{ Terraform, Excluded, Gaps int }
	byProduct, surfaces, deferrals := map[string]*count{}, map[string]int{}, map[string]int{}
	covered := 0
	for _, item := range value.Operations {
		for _, productID := range item.Products {
			if byProduct[productID] == nil {
				byProduct[productID] = &count{}
			}
			if item.Disposition == "terraform" {
				byProduct[productID].Terraform++
			} else {
				byProduct[productID].Excluded++
			}
			if item.ReleaseBlockingGap {
				byProduct[productID].Gaps++
			}
		}
		if item.Disposition == "terraform" {
			covered++
			for _, surface := range item.TerraformSurfaces {
				surfaces[surface]++
			}
		} else {
			deferrals[item.DeferReason.Code]++
		}
	}
	var out strings.Builder
	fmt.Fprint(&out, "# Mimecast API 2.0 Capability Coverage\n\n")
	fmt.Fprintf(&out, "Checked against the [official Mimecast API catalogue](%s) on %s. The catalogue contains **%d products**, **%d product operation entries**, and **%d unique method and path operations**. Product entries are higher because %d operations appear in more than one product.\n\n", value.API.CatalogueURL, value.API.CheckedOn, value.API.ProductCount, value.API.ProductOperationCount, value.API.UniqueOperationCount, value.API.ProductOperationCount-value.API.UniqueOperationCount)
	fmt.Fprintf(&out, "Every operation is classified in [`capabilities/api-v2.json`](../capabilities/api-v2.json): **%d have an implemented typed Terraform surface**, **%d are excluded**, and **%d declarative gaps block release**.\n\n", covered, len(value.Operations)-covered, len(blockingGaps(value)))
	fmt.Fprint(&out, "## Coverage Definition\n\n")
	fmt.Fprint(&out, "Coverage means every current API operation is tied to a typed resource or data source, or has a stable, specific lifecycle or API limitation. Console-only settings remain outside coverage until Mimecast publishes an API contract. Excluding an operation with a documented complete and safe Terraform lifecycle creates a release-blocking gap; the checker does not accept a generic deferral.\n\n")
	fmt.Fprint(&out, "The live checker fails on new, removed, moved, unknown, or unclassified operations. It also validates product, permission, pagination, contract, test status, and generated surface documentation. Upstream specifications are never committed.\n\n")
	fmt.Fprintln(&out, "## Product Summary\n\n| API product | Terraform | Excluded | Blocking gaps | Total entries |\n| --- | ---: | ---: | ---: | ---: |")
	for _, item := range value.API.Products {
		c := byProduct[item.ID]
		fmt.Fprintf(&out, "| %s (`%s`) | %d | %d | %d | %d |\n", item.Title, item.ID, c.Terraform, c.Excluded, c.Gaps, c.Terraform+c.Excluded)
	}
	fmt.Fprintln(&out, "\nCounts include cross-listed operations in every applicable product.\n\n## Terraform Surfaces\n\n| Surface | Operations |\n| --- | ---: |")
	for _, key := range sortedKeys(surfaces) {
		fmt.Fprintf(&out, "| `%s` | %d |\n", key, surfaces[key])
	}
	fmt.Fprintln(&out, "\n## Stable Deferrals\n\n| Defer code | Operations |\n| --- | ---: |")
	for _, key := range sortedKeys(deferrals) {
		fmt.Fprintf(&out, "| `%s` | %d |\n", key, deferrals[key])
	}
	fmt.Fprintln(&out, "\n## Maintenance\n\n```sh\nmake capability-check\nmake capability-doc\nmake capability-refresh\nmake capability-release-check\n```\n\nA refresh marks new operations unclassified. Release checking also fails while [`docs/api-gaps.md`](./api-gaps.md) contains any operation.")
	return out.String()
}

func renderGaps(value manifest) string {
	gaps := blockingGaps(value)
	var out strings.Builder
	fmt.Fprint(&out, "# Mimecast API 2.0 Release-Blocking Gaps\n\n")
	if len(gaps) == 0 {
		fmt.Fprintln(&out, "No release-blocking declarative gap remains. Excluded declarative and configuration-discovery operations with specific lifecycle or API limitations remain recorded as stable deferrals in [`capabilities/api-v2.json`](../capabilities/api-v2.json) and [`docs/api-coverage.md`](./api-coverage.md).")
		return out.String()
	}
	fmt.Fprintf(&out, "The following **%d declarative operations** have no implemented typed surface. `make capability-release-check` fails until each operation is implemented or evidence shows that the published contract cannot support a stable lifecycle.\n\n", len(gaps))
	fmt.Fprintln(&out, "| Operation | Products | Defer code | Specific limitation |\n| --- | --- | --- | --- |")
	for _, item := range gaps {
		fmt.Fprintf(&out, "| `%s %s` | `%s` | `%s` | %s |\n", item.Method, item.Path, strings.Join(item.Products, "`, `"), item.DeferReason.Code, item.DeferReason.Detail)
	}
	return out.String()
}

func blockingGaps(value manifest) []operation {
	var result []operation
	for _, item := range value.Operations {
		if item.ReleaseBlockingGap {
			result = append(result, item)
		}
	}
	return result
}

func operationSetDigest(operations []operation) string {
	hash := sha256.New()
	for _, item := range operations {
		fmt.Fprintf(hash, "%s\t%s\t%s\n", item.Method, item.Path, strings.Join(item.Products, ","))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func operationKey(method, path string) string { return method + " " + path }
func appendUnique(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}
func isHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
func set(values ...string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "capabilitycheck:", err); os.Exit(1) }
