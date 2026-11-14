// Go vanity import server for go.vicoworks.com, as a Cloudflare Worker.
//
// The Go toolchain resolves an import path it does not recognise by fetching
// https://<path>?go-get=1 and reading two meta tags:
//
//   go-import  <module root> git <repository URL>   where to clone from
//   go-source  <module root> <home> <dir> <file>     where pkg.go.dev links source
//
// So `go get go.vicoworks.com/guard-rails-engine/pkg/guardrails` lands here,
// learns the module root is go.vicoworks.com/guard-rails-engine and the code
// lives on GitHub, and clones it from there. The code, CI and releases never
// move; only the name does. Requests from a browser are redirected to the
// package's documentation on pkg.go.dev.
//
// To publish another module under the same domain, add a line to MODULES.

const HOST = "go.vicoworks.com";

const MODULES = {
  // module path segment after the host -> repository and default branch
  "guard-rails-engine": {
    repo: "https://github.com/VicoAritonang/guard-rails-engine",
    branch: "main",
  },
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    }

    const segments = url.pathname.split("/").filter(Boolean);
    if (segments.length === 0) {
      return index();
    }

    // Major-version suffixes (/v2, /v3) stay part of the module root, as
    // semantic import versioning requires.
    const name = segments[0];
    const mod = MODULES[name];
    if (!mod) {
      return new Response(`unknown module ${HOST}/${name}\n`, {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }
    let root = `${HOST}/${name}`;
    if (segments[1] && /^v[2-9]\d*$/.test(segments[1])) {
      root += `/${segments[1]}`;
    }
    const fullPath = `${HOST}/${segments.join("/")}`;

    if (url.searchParams.get("go-get") === "1") {
      return goGet(root, fullPath, mod);
    }
    // A person: send them to the documentation of exactly what they asked for.
    return Response.redirect(`https://pkg.go.dev/${fullPath}`, 302);
  },
};

function goGet(root, fullPath, mod) {
  const tree = `${mod.repo}/tree/${mod.branch}{/dir}`;
  const blob = `${mod.repo}/blob/${mod.branch}{/dir}/{file}#L{line}`;
  const body = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="go-import" content="${root} git ${mod.repo}">
<meta name="go-source" content="${root} ${mod.repo} ${tree} ${blob}">
<meta http-equiv="refresh" content="0; url=https://pkg.go.dev/${fullPath}">
<title>${escapeHTML(fullPath)}</title>
</head>
<body>
<p><code>go get ${escapeHTML(fullPath)}</code></p>
<p>Source: <a href="${mod.repo}">${mod.repo}</a> ·
Docs: <a href="https://pkg.go.dev/${fullPath}">pkg.go.dev/${escapeHTML(fullPath)}</a></p>
</body>
</html>
`;
  return new Response(body, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // The answer only changes when MODULES does; let the edge keep it.
      "Cache-Control": "public, max-age=3600",
    },
  });
}

function index() {
  const rows = Object.entries(MODULES)
    .map(([name, m]) => `<li><a href="https://pkg.go.dev/${HOST}/${name}"><code>${HOST}/${name}</code></a> · <a href="${m.repo}">source</a></li>`)
    .join("\n");
  return new Response(`<!doctype html>
<html><head><meta charset="utf-8"><title>${HOST}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem}code{font-size:.95em}</style>
</head><body>
<h1>${HOST}</h1>
<p>Go modules published under this domain:</p>
<ul>
${rows}
</ul>
</body></html>
`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}

function escapeHTML(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
