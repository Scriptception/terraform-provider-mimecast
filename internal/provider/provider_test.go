package provider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestProviderMetadata(t *testing.T) {
	p := New("test")()
	var resp provider.MetadataResponse
	p.Metadata(context.Background(), provider.MetadataRequest{}, &resp)
	if resp.TypeName != "mimecast" {
		t.Fatalf("TypeName = %q", resp.TypeName)
	}
	if resp.Version != "test" {
		t.Fatalf("Version = %q", resp.Version)
	}
}

func TestProviderSurfaces(t *testing.T) {
	p := New("test")()
	if got := len(p.Resources(context.Background())); got != 31 {
		t.Fatalf("resources = %d, want 31 safe lifecycle resources", got)
	}
	if got := len(p.DataSources(context.Background())); got != 36 {
		t.Fatalf("data sources = %d, want 36 typed inventory surfaces", got)
	}
}

func TestUnsafeLifecycleResourcesAreNotRegistered(t *testing.T) {
	p := New("test")()
	names := map[string]bool{}
	for _, factory := range p.Resources(context.Background()) {
		var response resource.MetadataResponse
		factory().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "mimecast"}, &response)
		names[response.TypeName] = true
	}
	for _, forbidden := range []string{"mimecast_connector", "mimecast_pending_domain"} {
		if names[forbidden] {
			t.Fatalf("unsafe lifecycle resource %q is registered", forbidden)
		}
	}
}

func TestAllResourcesAreTypedAndUniquelyNamed(t *testing.T) {
	p := New("test")()
	names := map[string]bool{}
	for _, factory := range p.Resources(context.Background()) {
		instance := factory()
		var metadata resource.MetadataResponse
		instance.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		if names[metadata.TypeName] {
			t.Fatalf("duplicate resource %q", metadata.TypeName)
		}
		names[metadata.TypeName] = true
		var schemaResponse resource.SchemaResponse
		instance.Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
		if schemaResponse.Diagnostics.HasError() {
			t.Fatalf("schema diagnostics for %q: %v", metadata.TypeName, schemaResponse.Diagnostics)
		}
		for attribute := range schemaResponse.Schema.Attributes {
			if attribute == "json" || len(attribute) > 5 && attribute[len(attribute)-5:] == "_json" {
				t.Fatalf("resource %q exposes raw JSON attribute %q", metadata.TypeName, attribute)
			}
		}
	}
	for _, required := range []string{
		"mimecast_cloud_integrated_policy",
		"mimecast_dmarc_managed_domain",
		"mimecast_dmarc_domain_group_association",
		"mimecast_active_directory_integration",
		"mimecast_address_alteration_policy",
		"mimecast_threat_reporting_subscription",
		"mimecast_journaling_service",
	} {
		if !names[required] {
			t.Fatalf("required typed resource %q is not registered", required)
		}
	}
}

func TestAllDataSourcesAreTypedAndUniquelyNamed(t *testing.T) {
	p := New("test")()
	names := map[string]bool{}
	for _, factory := range p.DataSources(context.Background()) {
		instance := factory()
		var metadata datasource.MetadataResponse
		instance.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		if names[metadata.TypeName] {
			t.Fatalf("duplicate data source %q", metadata.TypeName)
		}
		names[metadata.TypeName] = true
		var schemaResponse datasource.SchemaResponse
		instance.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResponse)
		if schemaResponse.Diagnostics.HasError() {
			t.Fatalf("schema diagnostics for %q: %v", metadata.TypeName, schemaResponse.Diagnostics)
		}
		if _, rawJSON := schemaResponse.Schema.Attributes["json"]; rawJSON {
			t.Fatalf("data source %q exposes raw JSON", metadata.TypeName)
		}
	}
	for _, required := range []string{
		"mimecast_account",
		"mimecast_emergency_contact",
		"mimecast_roles",
		"mimecast_greylisting_policies",
		"mimecast_outbound_ip_addresses",
		"mimecast_dmarc_domains",
		"mimecast_dmarc_policy_presets",
		"mimecast_dmarc_users",
		"mimecast_address_alteration_definitions",
		"mimecast_address_alteration_policies",
		"mimecast_threat_reporting_subscriptions",
	} {
		if !names[required] {
			t.Fatalf("required typed data source %q is not registered", required)
		}
	}
}

func TestRegisteredSurfacesMatchCapabilityManifest(t *testing.T) {
	type manifestOperation struct {
		TerraformSurfaces []string `json:"terraform_surfaces"`
	}
	type manifest struct {
		Operations []manifestOperation `json:"operations"`
	}

	content, err := os.ReadFile(filepath.Join("..", "..", "capabilities", "api-v2.json"))
	if err != nil {
		t.Fatalf("read capability manifest: %v", err)
	}
	var capabilities manifest
	if err := json.Unmarshal(content, &capabilities); err != nil {
		t.Fatalf("decode capability manifest: %v", err)
	}

	documented := map[string]bool{}
	for _, operation := range capabilities.Operations {
		for _, surface := range operation.TerraformSurfaces {
			documented[surface] = true
		}
	}
	registered := map[string]bool{}
	p := New("test")()
	for _, factory := range p.Resources(context.Background()) {
		var metadata resource.MetadataResponse
		factory().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		registered["resource."+metadata.TypeName] = true
	}
	for _, factory := range p.DataSources(context.Background()) {
		var metadata datasource.MetadataResponse
		factory().Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "mimecast"}, &metadata)
		registered["data_source."+metadata.TypeName] = true
	}

	missingFromManifest := setDifference(registered, documented)
	missingFromProvider := setDifference(documented, registered)
	if len(missingFromManifest) > 0 || len(missingFromProvider) > 0 {
		t.Fatalf("capability surface mismatch: registered but undocumented=%v; documented but unregistered=%v", missingFromManifest, missingFromProvider)
	}
}

func setDifference(left, right map[string]bool) []string {
	var result []string
	for value := range left {
		if !right[value] {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
