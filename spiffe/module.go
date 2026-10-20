// Package caddyspiffe lets Caddy use SPIFFE identities directly instead of
// ACME or static certificate files.
//
// Two modules are provided:
//
//	tls.get_certificate.spiffe    serve the workload's current X.509-SVID
//	tls.ca_pool.source.spiffe     trust the current SPIRE trust bundle
//
// Both read from the local SPIRE Agent's Workload API. The certificate module is
// a certmagic "Manager", which Caddy consults on every TLS handshake, so an
// SVID rotation is picked up without a Caddy reload, without writing keys to
// disk and without an extra sidecar process.
package caddyspiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func init() {
	caddy.RegisterModule(SVIDSource{})
	caddy.RegisterModule(TrustBundle{})
}

// defaultSocket is the SPIFFE Workload API endpoint used when none is set.
const defaultSocket = "/run/spire/agent/public/api.sock"

// SVIDSource serves the workload's current X.509-SVID.
//
// It is registered in the `tls.get_certificate` namespace, which certmagic
// consults during every handshake, so the served certificate always matches the
// SVID the Agent currently holds.
type SVIDSource struct {
	// Workload API socket. Defaults to the SPIRE Agent's public socket.
	SocketPath string `json:"socket_path,omitempty"`
	// Optional SPIFFE ID. When set, the source fails instead of serving a
	// different identity, which catches a wrong registration early.
	SPIFFEID string `json:"spiffe_id,omitempty"`

	source *workloadapi.X509Source
}

// CaddyModule implements caddy.Module.
func (SVIDSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.spiffe",
		New: func() caddy.Module { return new(SVIDSource) },
	}
}

// Provision opens the workload API stream.
func (s *SVIDSource) Provision(ctx caddy.Context) error {
	if s.SPIFFEID != "" {
		if _, err := spiffeid.FromString(s.SPIFFEID); err != nil {
			return fmt.Errorf("invalid spiffe_id: %w", err)
		}
	}
	source, err := newX509Source(ctx, s.SocketPath)
	if err != nil {
		return err
	}
	s.source = source
	ctx.OnCancel(func() { _ = source.Close() })
	return nil
}

// GetCertificate returns the current SVID for every handshake.
func (s SVIDSource) GetCertificate(_ context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.source == nil {
		return nil, errors.New("SPIFFE source is not provisioned")
	}
	svid, err := s.source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("get X.509-SVID: %w", err)
	}
	if s.SPIFFEID != "" && svid.ID.String() != s.SPIFFEID {
		return nil, fmt.Errorf("agent holds %s, configured %s", svid.ID, s.SPIFFEID)
	}

	chain := make([][]byte, 0, len(svid.Certificates))
	for _, certificate := range svid.Certificates {
		chain = append(chain, certificate.Raw)
	}
	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}, nil
}

// TrustBundle provides the current SPIFFE trust bundle as a client CA pool.
//
// Caddy builds the pool once per configuration, so a CA rotation is picked up on
// the next reload. That is coarser than SVID rotation, which needs no reload.
type TrustBundle struct {
	// Workload API socket. Defaults to the SPIRE Agent's public socket.
	SocketPath string `json:"socket_path,omitempty"`

	client *workloadapi.Client
}

// CaddyModule implements caddy.Module.
func (TrustBundle) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.ca_pool.source.spiffe",
		New: func() caddy.Module { return new(TrustBundle) },
	}
}

// Provision connects to the workload API.
func (b *TrustBundle) Provision(ctx caddy.Context) error {
	socketPath := b.SocketPath
	if socketPath == "" {
		socketPath = defaultSocket
	}
	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+socketPath))
	if err != nil {
		return fmt.Errorf("connect to the SPIFFE workload API at %s: %w", socketPath, err)
	}
	b.client = client
	ctx.OnCancel(func() { _ = client.Close() })
	return nil
}

// CertPool returns the trust bundle as a certificate pool.
//
// The pool is built once per configuration, so a trust domain CA rotation is
// picked up on the next reload. SVID rotation needs no reload.
func (b TrustBundle) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if b.client == nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bundles, err := b.client.FetchX509Bundles(ctx)
	if err != nil {
		return pool
	}
	for _, bundle := range bundles.Bundles() {
		for _, certificate := range bundle.X509Authorities() {
			pool.AddCert(certificate)
		}
	}
	return pool
}

// newX509Source connects to the agent and keeps the SVID stream open.
func newX509Source(ctx context.Context, socketPath string) (*workloadapi.X509Source, error) {
	if socketPath == "" {
		socketPath = defaultSocket
	}
	source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socketPath)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to the SPIFFE workload API at %s: %w", socketPath, err)
	}
	return source, nil
}

// pemEncode is kept for diagnostics: operators often want to inspect the bundle
// that produced a certificate pool.
func pemEncode(certificates []*x509.Certificate) []byte {
	var out []byte
	for _, certificate := range certificates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return out
}

var (
	_ caddy.Module      = (*SVIDSource)(nil)
	_ caddy.Provisioner = (*SVIDSource)(nil)
	_ certmagic.Manager = (*SVIDSource)(nil)
	_ caddy.Module      = (*TrustBundle)(nil)
	_ caddy.Provisioner = (*TrustBundle)(nil)
	_ caddytls.CA       = (*TrustBundle)(nil)
)
