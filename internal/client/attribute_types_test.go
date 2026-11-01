package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// All response bodies are synthetic fixtures based on the public contract.
func TestAttributeTypesRejectIncompleteInventory(t *testing.T) {
	for name, body := range map[string]string{
		"missing": `{}`, "null": `{"attributeTypes":null}`,
		"missing_id":     `{"attributeTypes":[{"prompt":"synthetic"}]}`,
		"duplicate_id":   `{"attributeTypes":[{"id":"synthetic-id"},{"id":"synthetic-id"}]}`,
		"repeated_token": `{"attributeTypes":[],"meta":{"nextPage":"synthetic-token"}}`,
		"invalid_type":   `{"attributeTypes":[{"id":"synthetic-id","promptType":"secret-body"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					fmt.Fprint(w, `{"access_token":"synthetic-token","expires_in":3600}`)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer s.Close()
			c, err := New(Config{BaseURL: s.URL, TokenURL: s.URL + "/oauth/token", ClientID: "id", ClientSecret: "synthetic", ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			items, err := c.ListAttributeTypes(context.Background())
			if err == nil || items != nil {
				t.Fatalf("accepted incomplete inventory: %v", err)
			}
			if strings.Contains(err.Error(), "secret-body") {
				t.Fatal("response body exposed")
			}
		})
	}
}

func TestAttributeTypesAcceptEmptyInventory(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			fmt.Fprint(w, `{"access_token":"synthetic-token","expires_in":3600}`)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/directory/v1/attributeTypes" || r.URL.Query().Get("pageSize") != "2" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		fmt.Fprint(w, `{"attributeTypes":[],"meta":{}}`)
	}))
	defer s.Close()
	c, err := New(Config{BaseURL: s.URL, TokenURL: s.URL + "/oauth/token", ClientID: "id", ClientSecret: "synthetic", ReadOnly: true, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	items, err := c.ListAttributeTypes(context.Background())
	if err != nil || items == nil || len(items) != 0 {
		t.Fatalf("empty inventory: %#v %v", items, err)
	}
}
