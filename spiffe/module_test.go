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
		"tls.get_certificate.spiffe":      new(SVIDSource),
		"tls.client_auth.verifier.spiffe": new(ClientVerifier),
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

func TestSVIDSourceRequiresProvisioning(t *testing.T) {
	if _, err := (SVIDSource{}).GetCertificate(nil, nil); err == nil {
		t.Fatal("expected an error without a provisioned source")
	}
}
