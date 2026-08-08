package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckedManifest(t *testing.T) {
	value, err := readManifest(filepath.Join("..", "..", "capabilities", "api-v2.json"))
	if err != nil {
		t.Fatalf("readManifest() error = %v", err)
	}
	if err := validateManifest(value); err != nil {
		t.Fatalf("validateManifest() error = %v", err)
	}
}

func checkedManifest(item operation) manifest {
	value := manifest{
		SchemaVersion: 1,
		API: apiMetadata{
			Version:               "2.0",
			CatalogueURL:          catalogueURL,
			CheckedOn:             "2026-08-08",
			ProductCount:          1,
			ProductOperationCount: 1,
			UniqueOperationCount:  1,
			Products:              []product{{ID: "example", Title: "Example"}},
		},
		Operations: []operation{item},
	}
	value.API.OperationSetSHA256 = operationSetDigest(value.Operations)
	return value
}

func TestValidateManifestAcceptsCheckedTerraformSurface(t *testing.T) {
	item := operation{
		Method: "GET", Path: "/example", Products: []string{"example"},
		Category: "configuration_discovery", Pagination: "cursor",
		Permission:  permission{APIProducts: []string{"example"}, DocumentedRolePermissions: []string{"Example | Read"}, Source: "official_contract"},
		Disposition: "terraform", TerraformSurfaces: []string{"data_source.mimecast_example"},
		Reason: "Typed example discovery.", ContractStatus: "official_contract_checked", TestStatus: "synthetic_contract",
	}
	if err := validateManifest(checkedManifest(item)); err != nil {
		t.Fatalf("validateManifest() error = %v", err)
	}
}

func TestValidateManifestRejectsHiddenDeclarativeGap(t *testing.T) {
	item := operation{
		Method: "PATCH", Path: "/example", Products: []string{"example"},
		Category: "declarative_configuration", Pagination: "not_paginated",
		Permission:  permission{APIProducts: []string{"example"}, Source: "api_product_only"},
		Disposition: "excluded", Reason: "Deferred example.",
		DeferReason: &deferReason{Code: "operation_has_no_durable_state", Detail: "This generic reason must not conceal a feasible configuration lifecycle."},
	}
	err := validateManifest(checkedManifest(item))
	if err == nil || !strings.Contains(err.Error(), "hides a declarative gap") {
		t.Fatalf("validateManifest() error = %v, want hidden-gap failure", err)
	}
}

func TestValidateManifestAcceptsSpecificLifecycleLimitation(t *testing.T) {
	item := operation{
		Method: "PATCH", Path: "/example", Products: []string{"example"},
		Category: "declarative_configuration", Pagination: "not_paginated",
		Permission:  permission{APIProducts: []string{"example"}, Source: "api_product_only"},
		Disposition: "excluded", Reason: "No complete lifecycle.",
		DeferReason: &deferReason{Code: "no_safe_delete_contract", Detail: "The API exposes an update but no documented safe delete or reset contract."},
	}
	if err := validateManifest(checkedManifest(item)); err != nil {
		t.Fatalf("validateManifest() error = %v", err)
	}
}

func TestValidateManifestAcceptsMissingReadContract(t *testing.T) {
	item := operation{
		Method: "POST", Path: "/example/associations", Products: []string{"example"},
		Category: "declarative_configuration", Pagination: "not_paginated",
		Permission:  permission{APIProducts: []string{"example"}, Source: "api_product_only"},
		Disposition: "excluded", Reason: "Association membership cannot be read.",
		DeferReason: &deferReason{Code: "no_safe_read_contract", Detail: "The API can mutate an association but cannot read whether that association currently exists."},
	}
	if err := validateManifest(checkedManifest(item)); err != nil {
		t.Fatalf("validateManifest() error = %v", err)
	}
}

func TestRenderGapsIncludesBlockingOperation(t *testing.T) {
	item := operation{
		Method: "POST", Path: "/example", Products: []string{"example"},
		Category: "declarative_configuration", Pagination: "not_paginated",
		Permission:  permission{APIProducts: []string{"example"}, Source: "api_product_only"},
		Disposition: "excluded", Reason: "Typed surface missing.", ReleaseBlockingGap: true,
		DeferReason: &deferReason{Code: "typed_surface_missing", Detail: "The API exposes a complete lifecycle but no typed provider surface is implemented."},
	}
	report := renderGaps(checkedManifest(item))
	if !strings.Contains(report, "POST /example") || !strings.Contains(report, "typed_surface_missing") {
		t.Fatalf("renderGaps() = %q", report)
	}
}

func TestRenderGapsExplainsStableDeferralsWhenNothingBlocksRelease(t *testing.T) {
	report := renderGaps(manifest{})
	if !strings.Contains(report, "No release-blocking declarative gap remains") || !strings.Contains(report, "stable deferrals") {
		t.Fatalf("renderGaps() = %q", report)
	}
	if strings.Contains(report, "No declarative API operations lack") {
		t.Fatalf("renderGaps() makes an inaccurate zero-exclusion claim: %q", report)
	}
}

func TestCompareLiveRejectsUnknownOperation(t *testing.T) {
	item := operation{
		Method: "GET", Path: "/example", Products: []string{"example"},
		Category: "operational_data", Pagination: "not_paginated",
		Permission:  permission{APIProducts: []string{"example"}, Source: "api_product_only"},
		Disposition: "excluded", Reason: "Operational data.",
		DeferReason: &deferReason{Code: "operational_service_data", Detail: "The endpoint returns operational service data without a durable object lifecycle."},
	}
	live := liveCatalogue{
		Products:              []product{{ID: "example", Title: "Example"}},
		ProductOperationCount: 2,
		Operations: []liveOperation{
			{Method: "GET", Path: "/example", Products: []string{"example"}},
			{Method: "POST", Path: "/new", Products: []string{"example"}},
		},
	}
	err := compareLive(checkedManifest(item), live)
	if err == nil || !strings.Contains(err.Error(), "new unclassified operation POST /new") {
		t.Fatalf("compareLive() error = %v", err)
	}
}
