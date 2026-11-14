# go.vicoworks.com: the Go import path

The Go module is named `go.vicoworks.com/guard-rails-engine`, while its code,
issues, CI and releases live at
`github.com/VicoAritonang/guard-rails-engine`. This Worker is what connects
the two. When `go get` sees an import path it does not know, it fetches the
path with `?go-get=1` and reads the `go-import` meta tag in the answer:

```text
$ curl -s 'https://go.vicoworks.com/guard-rails-engine/pkg/guardrails?go-get=1' | grep go-
<meta name="go-import" content="go.vicoworks.com/guard-rails-engine git https://github.com/VicoAritonang/guard-rails-engine">
<meta name="go-source" content="go.vicoworks.com/guard-rails-engine https://github.com/... {/dir} ...">
```

Browsers are redirected to the package's page on pkg.go.dev. The domain can
move to another host later without breaking a single import, which is the
point of a vanity path.

## Deploy (once)

Requirements: `vicoworks.com` is a zone on your Cloudflare account, and
Node.js 18+ is installed.

```bash
cd deploy/cloudflare/go-vanity
npx wrangler login
npx wrangler deploy
```

The `custom_domain` route in `wrangler.toml` creates the DNS record and the
certificate for `go.vicoworks.com`, so do not add a CNAME by hand. If the name
already has a DNS record (for example from your portfolio setup), delete that
record first, or wrangler will refuse to attach the domain.

To deploy from the dashboard instead: Workers & Pages → Create → Worker → paste
`worker.js` → Deploy → Settings → Domains & Routes → Add → Custom domain →
`go.vicoworks.com`.

## Check it

```bash
curl -s 'https://go.vicoworks.com/guard-rails-engine?go-get=1' | grep go-import
GOPROXY=direct go list -m go.vicoworks.com/guard-rails-engine@latest   # straight from GitHub via the Worker
go list -m go.vicoworks.com/guard-rails-engine@latest                  # through proxy.golang.org
```

`go list -m ...@latest` only works after the repository has at least one
semver tag (`v0.1.0`). Before that, use `@main`.

## Add another module

Every Go project of yours can live under the same domain. Add one line to
`MODULES` in `worker.js` and redeploy:

```js
const MODULES = {
  "guard-rails-engine": { repo: "https://github.com/VicoAritonang/guard-rails-engine", branch: "main" },
  "another-project":    { repo: "https://github.com/VicoAritonang/another-project",    branch: "main" },
};
```

The new repository's `go.mod` must then say `module go.vicoworks.com/another-project`.

## Things that go wrong

| Symptom | Cause |
|---|---|
| `unrecognized import path "go.vicoworks.com/..."` | The Worker is not reachable, or returned something other than the meta tag. Run the `curl` above. |
| `module declares its path as github.com/... but was required as go.vicoworks.com/...` | You are fetching a commit from before the module path changed. Use `@v0.1.0` or newer, or `@main`. |
| `go get` keeps returning an old version, or "not found" after a fix | proxy.golang.org caches answers, including "not found", for a while. Use `GOPROXY=direct` to bypass it, or wait. |
| pkg.go.dev has no page | It indexes a version the first time someone fetches it through the proxy. The release workflow's `go-module` job does that on every tag. |
| `go: verifying module: checksum mismatch` | A tag was moved after it was fetched. Never re-tag a published version; release a new one. |
