# caddy-plugins

Caddy modules used by the `realm` NixOS configuration. They live here, in their
own repository, so `caddy.withPlugins` can reference them through the Go module
proxy instead of injecting a local store path into a fixed-output derivation.

Two independent Go modules, one per plugin:

| Directory | Module | Caddy modules |
|---|---|---|
| `srv/` | `github.com/oluoceps/caddy-plugins/srv` | `layer4.handlers.srv_proxy` |
| `spiffe/` | `github.com/oluoceps/caddy-plugins/spiffe` | `tls.get_certificate.spiffe`, `tls.ca_pool.source.spiffe` |

## Why a separate repository

`caddy.withPlugins` turns its plugin list into `xcaddy --with MODULE@VERSION`
inside a fixed-output derivation. A local `file://` or store-path plugin makes
that derivation reference a store path, which Nix rejects:

```
error: the fixed-output derivation '…' must not reference store paths but 1 such reference was found
```

Referencing a published module keeps the derivation reproducible on any machine.

## Consuming a module

```nix
pkgs.caddy.withPlugins {
  plugins = [
    "github.com/oluoceps/caddy-plugins/srv@v0.1.0"
    "github.com/oluoceps/caddy-plugins/spiffe@v0.1.0"
  ];
  hash = "sha256-…";
}
```

## Releasing

Go resolves a module in a subdirectory from a tag named after that directory:

```sh
git tag srv/v0.1.0
git tag spiffe/v0.1.0
git push origin main --tags
```

Between releases, a commit hash works too and needs no tag:

```sh
go list -m github.com/oluoceps/caddy-plugins/spiffe@<commit>
# → v0.0.0-20260101120000-<commit>
```

`caddy.withPlugins` accepts pseudo-versions: it only requires an `@` in each
entry.

The first fetch after a push may need a moment before `proxy.golang.org` and
`sum.golang.org` have indexed the new version. If a build fails with "unknown
revision", retry after a minute.

## Development

```sh
(cd srv && go test -race ./...)
(cd spiffe && go test -race ./...)
```

`srv/` covers SRV priority/weight selection, UDP-to-TCP fallback, address
refresh and stream teardown. `spiffe/` covers the module IDs and the empty trust
pool guarantee; its Workload API paths need a live SPIRE Agent.
