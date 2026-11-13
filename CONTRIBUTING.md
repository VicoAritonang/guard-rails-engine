# Contributing

Thanks for helping. The most useful contribution often needs no Go at all: a
prompt the engine got wrong is a test case nobody had.

## Ways to help

- **Report a detection miss or a false alarm.** Use the
  [detection report](https://github.com/VicoAritonang/guard-rails-engine/issues/new?template=detection_report.yml).
  Each one can become a labelled case in `testdata/eval`.
- **Add an integration.** A client, a framework example, or a provider adapter in
  `internal/providers`.
- **Improve a guard.** Rules live in `internal/guards`. A change has to hold up
  against the evaluation gate, described below.
- **Fix the docs.** If something took you an hour to work out, that is a bug.

Security vulnerabilities go through [SECURITY.md](SECURITY.md), not a public issue.

## Set up

You need Go 1.26 or newer (`go.mod` selects the exact toolchain). No API key is
needed: the mock provider and the evaluation corpus run offline.

```bash
git clone https://github.com/VicoAritonang/guard-rails-engine.git
cd guard-rails-engine
make check          # exactly what CI runs
make run-mock       # gateway on http://localhost:8080
```

`make help` lists everything else.

## Changing detection

Detection here is a claim backed by numbers, so a change comes with its evidence:

1. Add the failing case to `testdata/eval`, labelled, before changing any code.
   Benign cases count as much as attacks: a rule that catches more and flags
   clean traffic has not improved.
2. Make the change.
3. Run `make eval` and `make redteam`, and put the before and after numbers in the
   pull request.

The gates in the `Makefile` are minimums. Lowering one needs a reason in the pull
request, and so does adding a rule that only fits the corpus.

## Pull requests

- Keep each one to a single change, and open an issue first for anything large.
- Tests travel with the code. For a bug, write the test that fails first.
- `make check` passes, and `gofmt` has run.
- A significant design decision gets an ADR in `docs/adr/`.
- User-visible changes get a line under `Unreleased` in `CHANGELOG.md`.
- A comment explains why, not what. The existing code is the style guide.
- Generated files are regenerated, not edited by hand: `make matrix` for
  `docs/tool-matrix.md`, `make dashboard` for the Grafana dashboard.

Contributions are accepted under the [MIT License](LICENSE), and this project
follows a [code of conduct](CODE_OF_CONDUCT.md).

## Where things are

| Path | What it holds |
|---|---|
| `pkg/guardrails` | Public Go library: the engine, in process |
| `pkg/sdk` | Public Go client for a running gateway |
| `sdks/python`, `sdks/js` | Clients for other languages |
| `config/` | Policy engine, environment config, shipped profiles |
| `internal/guards` | The guards, one package per stage |
| `internal/agent` | Tool catalog, risk tiers, taint, approvals, broker |
| `internal/mcp` | MCP gateway and agent runtime |
| `internal/server` | HTTP surface, including the OpenAI-compatible proxy |
| `internal/eval` | Evaluation harness and red team |
| `testdata/eval` | The labelled corpus |

## Releasing

Maintainers only. Pushing a tag runs `.github/workflows/release.yml`.

1. Set the same version in `sdks/python/pyproject.toml` and `sdks/js/package.json`,
   and move `Unreleased` in `CHANGELOG.md` under it.
2. `git tag v0.1.0 && git push origin v0.1.0`

Needed once, before the first release:

- **Docker:** the first push creates the package as private. Set it to public under
  the repository's Packages settings.
- **PyPI:** add a trusted publisher for `guard-rails-engine` (workflow
  `release.yml`, environment `pypi`), then set the repository variable
  `PUBLISH_PYPI=true`.
- **npm:** publish the first version by hand with `npm publish` from `sdks/js`, add
  a trusted publisher (workflow `release.yml`, environment `npm`), then set
  `PUBLISH_NPM=true`.
- **GitHub:** enable private vulnerability reporting, Dependabot alerts and branch
  protection on `main`.
