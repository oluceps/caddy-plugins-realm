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
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
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
// Caddy asks for the pool while building each handshake configuration. The
// source keeps the Workload API update stream open, so each call returns the
// bundle currently held by the Agent.
type TrustBundle struct {
	// Workload API socket. Defaults to the SPIRE Agent's public socket.
	SocketPath string `json:"socket_path,omitempty"`

	mu      sync.RWMutex
	bundles *x509bundle.Set
}

// CaddyModule implements caddy.Module.
func (TrustBundle) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.ca_pool.source.spiffe",
		New: func() caddy.Module { return new(TrustBundle) },
	}
}

// Provision opens the workload API update stream and waits for its first bundle.
func (b *TrustBundle) Provision(ctx caddy.Context) error {
	socketPath := b.SocketPath
	if socketPath == "" {
		socketPath = defaultSocket
	}
	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+socketPath))
	if err != nil {
		return fmt.Errorf("connect to the SPIFFE workload API at %s: %w", socketPath, err)
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	ctx.OnCancel(func() {
		cancel()
		_ = client.Close()
	})

	ready := make(chan error, 1)
	go func() {
		err := client.WatchX509Bundles(watchCtx, bundleWatcher{bundle: b, ready: ready})
		if watchCtx.Err() == nil {
			b.mu.Lock()
			b.bundles = nil
			b.mu.Unlock()
		}
		if err != nil && watchCtx.Err() == nil {
			select {
			case ready <- err:
			default:
			}
		}
	}()

	select {
	case err := <-ready:
		if err != nil {
			cancel()
			_ = client.Close()
			return fmt.Errorf("watch SPIFFE trust bundles: %w", err)
		}
	case <-ctx.Done():
		cancel()
		_ = client.Close()
		return ctx.Err()
	}
	return nil
}

// CertPool copies the trust bundle currently held by the update watcher.
//
// Caddy calls this while building a handshake configuration, so a rotated CA is
// used by the next handshake. An unavailable watcher returns an empty pool,
// which rejects clients instead of trusting every certificate.
func (b *TrustBundle) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	b.mu.RLock()
	bundles := b.bundles
	b.mu.RUnlock()
	if bundles == nil {
		return pool
	}
	for _, bundle := range bundles.Bundles() {
		for _, certificate := range bundle.X509Authorities() {
			pool.AddCert(certificate)
		}
	}
	return pool
}

// bundleWatcher stores each trust bundle update and reports the first one.
type bundleWatcher struct {
	bundle *TrustBundle
	ready  chan<- error
}

// OnX509BundlesUpdate replaces the cached bundle set.
func (w bundleWatcher) OnX509BundlesUpdate(bundles *x509bundle.Set) {
	w.bundle.mu.Lock()
	w.bundle.bundles = bundles
	w.bundle.mu.Unlock()
	select {
	case w.ready <- nil:
	default:
	}
}

// OnX509BundlesWatchError reports a failure before the first bundle arrives.
func (w bundleWatcher) OnX509BundlesWatchError(err error) {
	select {
	case w.ready <- err:
	default:
	}
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
