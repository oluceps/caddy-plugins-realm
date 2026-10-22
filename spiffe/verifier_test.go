package caddyspiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
)

const verifierTestID = "spiffe://clients.test/allowed"

// Every published set and its bundles are immutable after publication. Readers
// retain their snapshot while a different set replaces it atomically.
type verifierTestSource struct {
	set atomic.Pointer[x509bundle.Set]
}

func (s *verifierTestSource) publish(roots ...*x509.Certificate) {
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("clients.test"), roots)
	s.set.Store(x509bundle.NewSet(bundle))
}

func (s *verifierTestSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	set := s.set.Load()
	if set == nil {
		return nil, errors.New("bundle source has no snapshot")
	}
	return set.GetX509BundleForTrustDomain(td)
}

func verifierTestVerifier(source x509bundle.Source) *ClientVerifier {
	id := spiffeid.RequireFromString(verifierTestID)
	return &ClientVerifier{
		AllowedIDs: []string{verifierTestID},
		source:     source,
		allowedIDs: map[spiffeid.ID]struct{}{id: {}},
	}
}

type verifierTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func verifierTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func verifierTestSign(t *testing.T, template, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func verifierTestRoot(t *testing.T, name string) verifierTestCA {
	t.Helper()
	key := verifierTestKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return verifierTestCA{verifierTestSign(t, template, template, key, key), key}
}

func verifierTestLeaf(t *testing.T, ca verifierTestCA, id string, edit func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key := verifierTestKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test workload"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if id != "" {
		u, err := url.Parse(id)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{u}
	}
	if edit != nil {
		edit(template)
	}
	cert := verifierTestSign(t, template, ca.cert, key, ca.key)
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

type verifierTestFixture struct {
	a, b, serverCA           verifierTestCA
	clientA, clientB, server tls.Certificate
	invalid                  map[string]tls.Certificate
}

func newVerifierTestFixture(t *testing.T) verifierTestFixture {
	t.Helper()
	f := verifierTestFixture{
		a: verifierTestRoot(t, "A"), b: verifierTestRoot(t, "B"),
		serverCA: verifierTestRoot(t, "trusted test server CA"),
		invalid:  make(map[string]tls.Certificate),
	}
	f.clientA = verifierTestLeaf(t, f.a, verifierTestID, nil)
	f.clientB = verifierTestLeaf(t, f.b, verifierTestID, nil)
	// The server uses conventional DNS PKI. Clients verify localhost and this
	// separate CA, so a client-side server identity error cannot hide a bypass.
	f.server = verifierTestLeaf(t, f.serverCA, "", func(c *x509.Certificate) {
		c.DNSNames = []string{"localhost"}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	f.invalid["expired"] = verifierTestLeaf(t, f.a, verifierTestID, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-2 * time.Hour)
		c.NotAfter = time.Now().Add(-time.Hour)
	})
	f.invalid["future"] = verifierTestLeaf(t, f.a, verifierTestID, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(time.Hour)
		c.NotAfter = time.Now().Add(2 * time.Hour)
	})
	f.invalid["no SPIFFE URI"] = verifierTestLeaf(t, f.a, "", nil)
	f.invalid["wrong URI scheme"] = verifierTestLeaf(t, f.a, "https://clients.test/allowed", nil)
	f.invalid["unexpected ID"] = verifierTestLeaf(t, f.a, "spiffe://clients.test/other", nil)
	f.invalid["wrong trust domain"] = verifierTestLeaf(t, f.a, "spiffe://elsewhere.test/allowed", nil)
	f.invalid["serverAuth only"] = verifierTestLeaf(t, f.a, verifierTestID, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	f.invalid["no digital signature"] = verifierTestLeaf(t, f.a, verifierTestID, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageKeyEncipherment
	})
	untrusted := verifierTestRoot(t, "untrusted")
	f.invalid["untrusted"] = verifierTestLeaf(t, untrusted, verifierTestID, nil)
	selfKey := verifierTestKey(t)
	selfTemplate := *f.clientA.Leaf
	selfTemplate.PublicKey = &selfKey.PublicKey
	selfCert := verifierTestSign(t, &selfTemplate, &selfTemplate, selfKey, selfKey)
	f.invalid["self signed"] = tls.Certificate{Certificate: [][]byte{selfCert.Raw}, PrivateKey: selfKey, Leaf: selfCert}

	// A clientAuth leaf beneath a serverAuth-only intermediate must fail even
	// though x509svid.Verify intentionally permits ExtKeyUsageAny.
	intermediateKey := verifierTestKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "server-only intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	intermediate := verifierTestSign(t, intermediateTemplate, f.a.cert, intermediateKey, f.a.key)
	constrained := verifierTestLeaf(t, verifierTestCA{intermediate, intermediateKey}, verifierTestID, nil)
	constrained.Certificate = append(constrained.Certificate, intermediate.Raw)
	f.invalid["serverAuth intermediate"] = constrained
	return f
}

func TestClientVerifierRejectsInvalidCertificates(t *testing.T) {
	f := newVerifierTestFixture(t)
	source := new(verifierTestSource)
	source.publish(f.a.cert)
	v := verifierTestVerifier(source)
	if err := v.VerifyClientCertificate(f.clientA.Certificate, nil); err != nil {
		t.Fatalf("valid SPIFFE client rejected: %v", err)
	}
	for name, cert := range f.invalid {
		t.Run(name, func(t *testing.T) {
			if err := v.VerifyClientCertificate(cert.Certificate, nil); err == nil {
				t.Fatal("accepted invalid client certificate")
			}
		})
	}
	for name, raw := range map[string][][]byte{
		"missing": nil, "empty DER": {{}}, "malformed DER": {[]byte("not a certificate")},
		"malformed intermediate": {f.clientA.Leaf.Raw, []byte("not a certificate")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := v.VerifyClientCertificate(raw, nil); err == nil {
				t.Fatal("accepted absent or malformed certificate chain")
			}
		})
	}
	for name, v := range map[string]*ClientVerifier{
		"unprovisioned": {}, "missing source": verifierTestVerifier(nil),
		"uninitialized source":    verifierTestVerifier(new(verifierTestSource)),
		"uninitialized allowlist": {source: source},
	} {
		t.Run(name, func(t *testing.T) {
			if err := v.VerifyClientCertificate(f.clientA.Certificate, nil); err == nil {
				t.Fatal("accepted client without initialized verifier state")
			}
		})
	}
}

func TestClientVerifierVerifiedChainsDoNotSubstituteTrust(t *testing.T) {
	f := newVerifierTestFixture(t)
	source := new(verifierTestSource)
	source.publish(f.a.cert)
	v := verifierTestVerifier(source)
	claimed := [][]*x509.Certificate{{f.clientB.Leaf, f.b.cert}}
	if err := v.VerifyClientCertificate(f.clientB.Certificate, claimed); err == nil {
		t.Fatal("verifiedChains bypassed the current bundle")
	}
	if err := v.VerifyClientCertificate(nil, [][]*x509.Certificate{{f.clientA.Leaf, f.a.cert}}); err == nil {
		t.Fatal("verifiedChains substituted a missing raw certificate")
	}
	if err := v.VerifyClientCertificate(f.clientA.Certificate, claimed); err != nil {
		t.Fatalf("unrelated verifiedChains overrode a valid raw SPIFFE chain: %v", err)
	}
	source.publish()
	if err := v.VerifyClientCertificate(f.clientA.Certificate, [][]*x509.Certificate{{f.clientA.Leaf, f.a.cert}}); err == nil {
		t.Fatal("verifiedChains retained trust after bundle removal")
	}
}

func TestClientVerifierConcurrentRotation(t *testing.T) {
	f := newVerifierTestFixture(t)
	source := new(verifierTestSource)
	source.publish(f.a.cert)
	v := verifierTestVerifier(source)
	old, err := source.GetX509BundleForTrustDomain(spiffeid.RequireTrustDomainFromString("clients.test"))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 100 {
				// A and B may succeed or fail during rotation. An invalid ID
				// must never succeed in any snapshot.
				_ = v.VerifyClientCertificate(f.clientA.Certificate, nil)
				_ = v.VerifyClientCertificate(f.clientB.Certificate, nil)
				if err := v.VerifyClientCertificate(f.invalid["unexpected ID"].Certificate, nil); err == nil {
					t.Error("rotation admitted an unexpected SPIFFE ID")
					return
				}
			}
		}()
	}
	close(start)
	for range 100 {
		source.publish(f.a.cert)
		source.publish(f.a.cert, f.b.cert)
		source.publish(f.b.cert)
		source.publish()
	}
	wg.Wait()
	for _, cert := range []tls.Certificate{f.clientA, f.clientB} {
		if err := v.VerifyClientCertificate(cert.Certificate, nil); err == nil {
			t.Fatal("client accepted after final empty publication")
		}
	}
	if roots := old.X509Authorities(); len(roots) != 1 || !roots[0].Equal(f.a.cert) {
		t.Fatal("publishing new bundles mutated an earlier snapshot")
	}
}

func TestClientVerifierInvalidAllowlist(t *testing.T) {
	for name, ids := range map[string][]string{
		"omitted": nil, "empty": {}, "empty ID": {""},
		"non SPIFFE":              {"https://clients.test/allowed"},
		"wildcard":                {"spiffe://clients.test/*"},
		"malformed":               {"spiffe:///missing-domain"},
		"mixed valid and invalid": {verifierTestID, "not-an-id"},
	} {
		t.Run(name, func(t *testing.T) {
			parent, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			ctx, cancel := caddy.NewContext(caddy.Context{Context: parent})
			defer cancel()
			raw, err := json.Marshal(map[string]any{"allowed_ids": ids, "socket_path": filepath.Join(t.TempDir(), "absent.sock")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ctx.LoadModuleByID("tls.client_auth.verifier.spiffe", raw)
			if err == nil {
				t.Fatal("invalid allowlist accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "allow") && !strings.Contains(strings.ToLower(err.Error()), "id") {
				t.Fatalf("configuration failed for a reason other than allowlist validation: %v", err)
			}
		})
	}
}

// This app gives the integration test a genuine Caddy provisioning context with
// a TLS app. Policies are decoded from JSON and provisioned through Caddy's
// public API; no test installs or mirrors a verification callback.
type verifierTestApp struct {
	Token    string                      `json:"token"`
	Policies caddytls.ConnectionPolicies `json:"policies"`
}

var verifierTestApps sync.Map // token -> func(caddytls.ConnectionPolicies) error

func init() { caddy.RegisterModule(verifierTestApp{}) }
func (verifierTestApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "spiffe_verifier_test", New: func() caddy.Module { return new(verifierTestApp) }}
}
func (a *verifierTestApp) Provision(ctx caddy.Context) error {
	if err := a.Policies.Provision(ctx); err != nil {
		return err
	}
	fn, ok := verifierTestApps.Load(a.Token)
	if !ok {
		return errors.New("unknown verifier test fixture")
	}
	return fn.(func(caddytls.ConnectionPolicies) error)(a.Policies)
}
func (*verifierTestApp) Start() error { return nil }
func (*verifierTestApp) Stop() error  { return nil }

// A minimal real Workload API server exercises production provisioning and
// bundle updates. Responses own their DER bytes and are never modified.
type verifierTestWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	updates chan *workload.X509BundlesResponse
	initial *workload.X509BundlesResponse
	svid    *workload.X509SVID
	active  atomic.Int32
}

func verifierTestResponse(roots ...*x509.Certificate) *workload.X509BundlesResponse {
	var der []byte
	for _, root := range roots {
		der = append(der, root.Raw...)
	}
	bundles := make(map[string][]byte)
	if len(der) != 0 {
		bundles["spiffe://clients.test"] = der
	}
	return &workload.X509BundlesResponse{Bundles: bundles}
}

func (s *verifierTestWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	s.active.Add(1)
	defer s.active.Add(-1)
	send := func(response *workload.X509BundlesResponse) error {
		return stream.Send(&workload.X509SVIDResponse{
			Svids: []*workload.X509SVID{s.svid}, FederatedBundles: response.Bundles,
		})
	}
	if err := send(s.initial); err != nil {
		return err
	}
	for {
		select {
		case resp := <-s.updates:
			if err := send(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *verifierTestWorkloadAPI) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	s.active.Add(1)
	defer s.active.Add(-1)
	if err := stream.Send(&workload.JWTBundlesResponse{}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// Report both ends: TLS 1.3 clients can finish their side before the server has
// rejected client authentication, so client.Handshake alone is insufficient.
func verifierTestHandshake(config *tls.Config, serverCA *x509.Certificate, clientCert *tls.Certificate) (serverErr, clientErr error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err, err
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return err, err
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		return err, err
	}
	defer server.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = server.SetDeadline(deadline)
	_ = client.SetDeadline(deadline)
	result := make(chan error, 1)
	go func() {
		result <- tls.Server(server, config).Handshake()
		_ = server.Close()
	}()
	roots := x509.NewCertPool()
	roots.AddCert(serverCA)
	clientConfig := &tls.Config{
		RootCAs: roots, ServerName: "localhost", MinVersion: config.MinVersion, MaxVersion: config.MaxVersion,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if clientCert == nil {
				return &tls.Certificate{}, nil
			}
			return clientCert, nil
		},
	}
	clientErr = tls.Client(client, clientConfig).Handshake()
	_ = client.Close()
	return <-result, clientErr
}

func TestClientVerifierCaddyHandshakes(t *testing.T) {
	f := newVerifierTestFixture(t)
	socket := filepath.Join(t.TempDir(), "workload.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	identity := verifierTestLeaf(t, f.serverCA, "spiffe://servers.test/observability", nil)
	key, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	api := &verifierTestWorkloadAPI{
		initial: verifierTestResponse(f.a.cert), updates: make(chan *workload.X509BundlesResponse, 1),
		svid: &workload.X509SVID{
			SpiffeId: "spiffe://servers.test/observability", X509Svid: identity.Certificate[0],
			X509SvidKey: key, Bundle: f.serverCA.cert.Raw,
		},
	}
	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, api)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	defer listener.Close()

	// Validate provisions the complete JSON configuration and runs these tests
	// while the source is live, then cancels all Caddy resources on return.
	token := t.Name()
	verifierTestApps.Store(token, func(policies caddytls.ConnectionPolicies) error {
		if len(policies) != 1 || policies[0].TLSConfig == nil {
			return errors.New("Caddy did not provision the TLS policy")
		}
		base := policies[0].TLSConfig
		if base.ClientAuth != tls.RequireAnyClientCert || base.ClientCAs != nil {
			return errors.New("expected require mode without a static client CA pool")
		}
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(tls.VersionName(version), func(t *testing.T) {
				config := base.Clone()
				config.Certificates = []tls.Certificate{f.server}
				config.GetCertificate = nil
				config.MinVersion, config.MaxVersion = version, version
				for _, phase := range []struct {
					name  string
					roots []*x509.Certificate
					a, b  bool
				}{
					{"A", []*x509.Certificate{f.a.cert}, true, false},
					{"A+B", []*x509.Certificate{f.a.cert, f.b.cert}, true, true},
					{"B", []*x509.Certificate{f.b.cert}, false, true},
					{"empty", nil, false, false},
				} {
					t.Run(phase.name, func(t *testing.T) {
						api.updates <- verifierTestResponse(phase.roots...)
						// Workload API publication is asynchronous. Wait for both
						// identities to demonstrate the requested snapshot, then
						// assert every handshake against that stable publication.
						deadline := time.Now().Add(5 * time.Second)
						for {
							aErr, acErr := verifierTestHandshake(config, f.serverCA.cert, &f.clientA)
							bErr, bcErr := verifierTestHandshake(config, f.serverCA.cert, &f.clientB)
							if (aErr == nil) == phase.a && (bErr == nil) == phase.b {
								if (phase.a && acErr != nil) || (phase.b && bcErr != nil) {
									t.Fatalf("client failed server verification: A=%v B=%v", acErr, bcErr)
								}
								break
							}
							if time.Now().After(deadline) {
								t.Fatalf("bundle update did not reach handshakes: A=%v B=%v", aErr, bErr)
							}
							runtime.Gosched()
						}
						cases := []struct {
							name string
							cert *tls.Certificate
							ok   bool
						}{
							{"client A", &f.clientA, phase.a}, {"client B", &f.clientB, phase.b}, {"missing certificate", nil, false},
						}
						for name, cert := range f.invalid {
							c := cert
							cases = append(cases, struct {
								name string
								cert *tls.Certificate
								ok   bool
							}{name, &c, false})
						}
						for _, tc := range cases {
							t.Run(tc.name, func(t *testing.T) {
								serverErr, clientErr := verifierTestHandshake(config, f.serverCA.cert, tc.cert)
								if (serverErr == nil) != tc.ok || (tc.ok && clientErr != nil) {
									t.Fatalf("want accepted=%t: server=%v client=%v", tc.ok, serverErr, clientErr)
								}
							})
						}
					})
				}
			})
		}
		return nil
	})
	defer verifierTestApps.Delete(token)
	appJSON, err := json.Marshal(map[string]any{
		"token": token,
		"policies": []any{map[string]any{"client_authentication": map[string]any{
			"mode": "require", "verifiers": []any{map[string]any{
				"verifier": "spiffe", "socket_path": socket, "allowed_ids": []string{verifierTestID},
			}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Validate(&caddy.Config{AppsRaw: caddy.ModuleMap{"spiffe_verifier_test": appJSON}}); err != nil {
		t.Fatal(fmt.Errorf("provision unpatched Caddy configuration: %w", err))
	}
	waitForNoWorkloadStreams(t, api)

	t.Run("server source cleanup", func(t *testing.T) {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()
		data, err := json.Marshal(map[string]any{
			"socket_path": socket, "spiffe_id": "spiffe://servers.test/observability",
		})
		if err != nil {
			t.Fatal(err)
		}
		module, err := ctx.LoadModuleByID("tls.get_certificate.spiffe", data)
		if err != nil {
			t.Fatal(err)
		}
		source := module.(*SVIDSource)
		if _, err := source.GetCertificate(nil, nil); err != nil {
			t.Fatal(err)
		}
		cancel()
		waitForNoWorkloadStreams(t, api)
		if _, err := source.GetCertificate(nil, nil); err == nil {
			t.Fatal("unloaded server source still serves an identity")
		}
		if err := source.Cleanup(); err != nil {
			t.Fatalf("repeated source cleanup: %v", err)
		}
	})
}

func waitForNoWorkloadStreams(t *testing.T, api *verifierTestWorkloadAPI) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for api.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("Caddy unload leaked %d Workload API streams", api.active.Load())
		}
		runtime.Gosched()
	}
}
