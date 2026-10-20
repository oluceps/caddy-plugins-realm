package caddyspiffe

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// The module IDs are the contract with the NixOS module; a rename here silently
// breaks deployed configuration.
func TestModuleContract(t *testing.T) {
	cases := map[string]caddy.Module{
		"tls.get_certificate.spiffe": new(SVIDSource),
		"tls.ca_pool.source.spiffe":  new(TrustBundle),
	}
	for id, want := range cases {
		info, err := caddy.GetModule(id)
		if err != nil {
			t.Fatalf("module %s is not registered: %v", id, err)
		}
		if got, wantType := fmt.Sprintf("%T", info.New()), fmt.Sprintf("%T", want); got != wantType {
			t.Errorf("module %s constructs %s, want %s", id, got, wantType)
		}
	}
}

func TestEmptyTrustBundleIsAnEmptyPool(t *testing.T) {
	// A pool without a connected client must be empty, never nil: Caddy assigns
	// it to `tls.Config.ClientCAs` and a nil pool would mean "trust everything".
	pool := TrustBundle{}.CertPool()
	if pool == nil {
		t.Fatal("CertPool returned nil")
	}
	if len(pool.Subjects()) != 0 {
		t.Fatalf("expected an empty pool, got %d subjects", len(pool.Subjects()))
	}
}

func TestSVIDSourceRequiresProvisioning(t *testing.T) {
	if _, err := (SVIDSource{}).GetCertificate(nil, nil); err == nil {
		t.Fatal("expected an error without a provisioned source")
	}
}
