// Package caddyspiffe supplies SPIFFE server identities and client verification.
// Both modules use the local SPIRE Agent's Workload API. Updates stay in memory
// and apply to new TLS connections without a Caddy reload.
package caddyspiffe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func init() {
	caddy.RegisterModule(SVIDSource{})
	caddy.RegisterModule(ClientVerifier{})
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

	source  *workloadapi.X509Source
	cleanup func() error
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
	s.cleanup = sync.OnceValue(source.Close)
	return nil
}

// Cleanup closes the Workload API stream when Caddy unloads the module.
func (s *SVIDSource) Cleanup() error {
	if s.cleanup == nil {
		return nil
	}
	return s.cleanup()
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

var (
	_ caddy.Module       = (*SVIDSource)(nil)
	_ caddy.Provisioner  = (*SVIDSource)(nil)
	_ caddy.CleanerUpper = (*SVIDSource)(nil)
	_ certmagic.Manager  = (*SVIDSource)(nil)
)
