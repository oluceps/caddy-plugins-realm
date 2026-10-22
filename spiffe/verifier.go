package caddyspiffe

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// ClientVerifier verifies client SVIDs against the current SPIRE trust bundles.
// Configure client_authentication.mode as "require" and omit its CA pool. This
// verifier performs chain verification and exact SPIFFE ID authorization.
type ClientVerifier struct {
	SocketPath string   `json:"socket_path,omitempty"`
	AllowedIDs []string `json:"allowed_ids,omitempty"`

	source     x509bundle.Source
	allowedIDs map[spiffeid.ID]struct{}
	cleanup    func() error
}

func (ClientVerifier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.spiffe",
		New: func() caddy.Module { return new(ClientVerifier) },
	}
}

// Provision validates the allowlist before opening the Workload API stream.
func (v *ClientVerifier) Provision(ctx caddy.Context) error {
	if len(v.AllowedIDs) == 0 {
		return errors.New("SPIFFE client verifier requires a nonempty allowed_ids list")
	}
	allowed := make(map[spiffeid.ID]struct{}, len(v.AllowedIDs))
	for _, value := range v.AllowedIDs {
		id, err := spiffeid.FromString(value)
		if err != nil {
			return fmt.Errorf("invalid allowed SPIFFE ID %q: %w", value, err)
		}
		allowed[id] = struct{}{}
	}

	socketPath := v.SocketPath
	if socketPath == "" {
		socketPath = defaultSocket
	}
	source, err := workloadapi.NewBundleSource(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socketPath)),
	)
	if err != nil {
		return fmt.Errorf("connect to the SPIFFE workload API at %s: %w", socketPath, err)
	}
	v.allowedIDs = allowed
	v.source = source
	v.cleanup = sync.OnceValue(source.Close)
	return nil
}

// Cleanup closes the Workload API streams when Caddy unloads the module.
func (v *ClientVerifier) Cleanup() error {
	if v.cleanup == nil {
		return nil
	}
	return v.cleanup()
}

// VerifyClientCertificate always verifies the raw chain against a fresh bundle.
// Caddy invokes it through VerifyConnection. Previously verified chains do not
// replace the current trust decision, including after a CA has been removed.
func (v *ClientVerifier) VerifyClientCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if v.source == nil || len(v.allowedIDs) == 0 {
		return errors.New("SPIFFE client verifier is not provisioned")
	}
	if len(rawCerts) == 0 {
		return errors.New("SPIFFE client certificate is required")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse SPIFFE certificate %d: %w", i, err)
		}
		certs[i] = cert
	}
	id, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return fmt.Errorf("read client SPIFFE ID: %w", err)
	}
	bundle, err := v.source.GetX509BundleForTrustDomain(id.TrustDomain())
	if err != nil {
		return fmt.Errorf("get SPIFFE trust bundle: %w", err)
	}
	if bundle == nil {
		return errors.New("SPIFFE trust bundle is unavailable")
	}
	// Use one immutable bundle snapshot for both verification steps.
	if _, _, err := x509svid.Verify(certs, bundle); err != nil {
		return fmt.Errorf("verify client SVID: %w", err)
	}
	if certs[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("client SVID requires digitalSignature key usage")
	}
	// x509svid.Verify accepts any extended key usage. Also enforce Go TLS's
	// client-auth purpose, including restrictions imposed by intermediates.
	roots := x509.NewCertPool()
	for _, authority := range bundle.X509Authorities() {
		roots.AddCert(authority)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("verify client-auth certificate usage: %w", err)
	}
	if _, ok := v.allowedIDs[id]; !ok {
		return fmt.Errorf("client SPIFFE ID %q is not allowed", id)
	}
	return nil
}

var (
	_ caddy.Module                       = (*ClientVerifier)(nil)
	_ caddy.Provisioner                  = (*ClientVerifier)(nil)
	_ caddy.CleanerUpper                 = (*ClientVerifier)(nil)
	_ caddytls.ClientCertificateVerifier = (*ClientVerifier)(nil)
)
