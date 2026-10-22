# caddy-plugins

SPIFFE modules for the Realm NixOS configuration. They use Caddy's public
extension interfaces and require no Caddy source patch.

The `spiffe/` Go module registers two Caddy modules:

| Module | Purpose |
|---|---|
| `tls.get_certificate.spiffe` | Serve the current X.509-SVID from the SPIRE Agent. |
| `tls.client_auth.verifier.spiffe` | Verify client SVIDs against current trust bundles and an exact identity allowlist. |

## Client authentication

Use the verifier with `client_authentication.mode = "require"`. Caddy requires
a client certificate, and the verifier performs certificate verification and
authorization. Do not configure a separate `ca` or `trust_pool` for this policy.
Those settings use Caddy's CA pool snapshot and can reject a rotated CA before
the verifier runs.

```json
{
  "client_authentication": {
    "mode": "require",
    "verifiers": [
      {
        "verifier": "spiffe",
        "socket_path": "/run/spire/agent/public/api.sock",
        "allowed_ids": ["spiffe://nyaw.xyz/service/vmagent"]
      }
    ]
  }
}
```

`allowed_ids` must contain at least one valid, exact SPIFFE ID. Wildcards are
not supported. The verifier rejects missing certificates, invalid SVIDs,
untrusted chains, expired certificates, and identities outside this list.
It also checks the client-auth purpose throughout the certificate chain.
The verifier does not trust a SPIFFE URI without a valid certificate chain.

The verifier reads the current trust bundle for every connection. It uses one
bundle snapshot for both SVID and client-auth verification. Removed CAs stop
validating new connections. Existing connections keep their established TLS
session until they close. Caddy invokes the verifier through `VerifyConnection`.

The server certificate module keeps its existing configuration:

```json
{
  "get_certificate": [
    {
      "via": "spiffe",
      "socket_path": "/run/spire/agent/public/api.sock",
      "spiffe_id": "spiffe://nyaw.xyz/service/observability-eihort"
    }
  ]
}
```

Both modules use the local SPIRE Workload API. Keys remain in memory. The
identity and trust-bundle streams update without a Caddy reload.

## Migration

The SRV proxy module was removed because Realm connects directly to catalog
endpoints. The old `tls.ca_pool.source.spiffe` module was replaced by the client
verifier. Replace `mode = "require_and_verify"` and `ca.provider = "spiffe"`
with the verifier policy above before upgrading the plugin.

After all listeners use the verifier, remove the Caddy CA rotation patch and
its build-time test injection. Keep the HTTP path, method, and query policies.

## Published builds

`caddy.withPlugins` fetches plugins inside a fixed-output derivation. Use a
published Go module version or commit. A local checkout inside that derivation
creates a Nix store reference and prevents a reproducible fixed-output build.

For a release of the subdirectory module:

```sh
git tag spiffe/v0.2.0
git push origin main spiffe/v0.2.0
```

Then use `github.com/oluceps/caddy-plugins-realm/spiffe@v0.2.0` in the Nix plugin
list and update its dependency hash. Between releases, resolve a published
commit with `go list -m` and use the resulting pseudo-version.

## Development

```sh
cd spiffe
go test -race -count=1 ./...
go vet ./...
```

The tests use generated certificates and local TLS connections. They do not
need production credentials.
