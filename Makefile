# Guardrails Engine
#
# The default target is `check`, which is exactly what CI runs. If it passes
# locally it passes in CI, and that property is worth more than any individual
# target here.

MODULE  := go.vicoworks.com/guard-rails-engine
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD   := build
DATASET ?= testdata/eval

# Quality gates. These are the numbers CI enforces; raising them is a
# deliberate act, lowering them should require an explanation in the PR.
MIN_F1          ?= 0.90
MAX_BENIGN_FPR  ?= 0.05
MAX_P99         ?= 50ms
MIN_CATCH_RATE  ?= 0.90

.DEFAULT_GOAL := check
.PHONY: vuln check build test race lint vet fmt eval redteam sweep bench cover run scan clean docker docker-run tidy ci tools agent matrix up down loadgen experiments experiment-offline dashboard bench-fetch benchmarks mcp-demo

## check: everything CI runs
check: fmt vet test eval redteam agent

## build: compile both binaries into build/
build:
	@mkdir -p $(BUILD)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD)/ ./cmd/...
	@echo "built $(BUILD)/ at version $(VERSION)"

## test: unit tests with the race detector
test:
	go test -race -count=1 ./...

## race: alias kept for muscle memory
race: test

## bench: latency and allocation benchmarks
bench:
	go test -run '^$$' -bench . -benchmem ./internal/...

## cover: coverage report
cover:
	go test -coverprofile=$(BUILD)/coverage.out -covermode=atomic ./...
	go tool cover -func=$(BUILD)/coverage.out | tail -1
	go tool cover -html=$(BUILD)/coverage.out -o $(BUILD)/coverage.html
	@echo "report at $(BUILD)/coverage.html"

## vuln: check dependencies and the toolchain for known vulnerabilities
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## vet: static analysis
vet:
	go vet ./...

## fmt: verify formatting (fails rather than rewrites, so CI can use it)
fmt:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "run: gofmt -w ." && exit 1)

## tidy: verify go.mod is current
tidy:
	go mod tidy -diff

## eval: score the labelled corpus and enforce the quality gates
eval:
	@mkdir -p $(BUILD)/eval
	go run ./cmd/grctl eval \
		--dataset $(DATASET) \
		--out $(BUILD)/eval \
		--quiet \
		--min-f1 $(MIN_F1) \
		--max-benign-fpr $(MAX_BENIGN_FPR) \
		--max-p99 $(MAX_P99)
	@echo "eval passed; report at $(BUILD)/eval/report.md"

## redteam: measure resistance to evasion variants
redteam:
	@mkdir -p $(BUILD)
	go run ./cmd/grctl redteam \
		--dataset $(DATASET) \
		--min-catch-rate $(MIN_CATCH_RATE) > $(BUILD)/redteam.md
	@grep -E "Overall catch rate" $(BUILD)/redteam.md
	@echo "full red-team report at $(BUILD)/redteam.md"

## tools: print the tool risk matrix (tiers, exposure, required controls)
tools:
	@go run ./cmd/grctl tools --verbose

## matrix: regenerate docs/tool-matrix.md from the catalog
#
# Generated, never hand-written. A risk matrix maintained by hand is wrong the
# first time somebody adds a tool, and wrong in the direction that matters.
matrix:
	@go run ./cmd/grctl tools --format markdown --verbose > docs/tool-matrix.md
	@echo "docs/tool-matrix.md updated"

## agent: replay the scripted agent attack scenarios
#
# Every scenario asserts what should happen, so this is an integration test with
# readable output: it exits non-zero if any control stops behaving as documented.
agent:
	@go run ./cmd/grctl agent

## sweep: precision/recall curve for the injection threshold
sweep:
	@mkdir -p $(BUILD)/eval
	go run ./cmd/grctl eval --dataset $(DATASET) --sweep injection:injection \
		--out $(BUILD)/eval --quiet
	@echo "sweep written to $(BUILD)/eval/report.md"

## report: full report (eval + red team + sweep) to docs/eval-report.md
report:
	@mkdir -p $(BUILD)/eval
	go run ./cmd/grctl eval --dataset $(DATASET) --redteam \
		--sweep injection:injection --out $(BUILD)/eval --quiet
	@cp $(BUILD)/eval/report.md docs/eval-report.md
	@echo "docs/eval-report.md updated"

## run: start the gateway, reading credentials from .env
#
# Deliberately sets nothing itself. A real environment variable outranks .env,
# so exporting a default here would silently override the provider and key the
# developer just put in their .env file -- and the symptom would be "my OpenAI
# key is being ignored" with nothing to point at.
run:
	go run ./cmd/server

## run-mock: start the gateway with no upstream, for a demo without a key
run-mock:
	GUARDRAILS_PROVIDER=mock \
	go run ./cmd/server

## scan: one-off scan, e.g. make scan TEXT="ignore all previous instructions"
scan:
	@go run ./cmd/grctl scan --text "$(TEXT)" --verbose

## docker: build the container image
docker:
	docker build -t guardrails-engine:$(VERSION) --build-arg VERSION=$(VERSION) .

## docker-run: run the image locally
docker-run:
	docker run --rm -p 127.0.0.1:8080:8080 guardrails-engine:$(VERSION)

## up: gateway + Prometheus + Grafana + Jaeger + Loki (docker compose)
up:
	docker compose up -d --build
	@echo "showcase http://localhost:8080 · console http://localhost:8080/console · grafana http://localhost:3000 · jaeger http://localhost:16686 · prometheus http://localhost:9090"

## down: stop the stack
down:
	docker compose down

## loadgen: drive mixed traffic through the running stack
loadgen:
	docker compose --profile load run --rm loadgen --requests 150 --rps 1

## experiments: run the full evidence suite against real models (needs keys)
#
# Model calls are recorded in experiments/.callcache, so a re-run replays them
# for free; pass ARGS=--fresh to re-query every model.
experiments:
	go run ./cmd/grctl experiment $(ARGS) all
	@echo "ledger: experiments/index.html"

## bench-fetch: download the public benchmarks (revisions pinned in a manifest)
bench-fetch:
	go run ./cmd/grctl experiment fetch

## benchmarks: score rules vs model classifiers on the public benchmarks
benchmarks:
	go run ./cmd/grctl experiment --per-bench 160 --slow-sample 24 benchmarks

## mcp-demo: run the hostile demo MCP server locally on :8090
mcp-demo:
	go run ./cmd/grctl mcp-demo

## experiment-offline: the experiment that needs no API key (seeded fault injection)
experiment-offline:
	go run ./cmd/grctl experiment resilience

## dashboard: regenerate the Grafana dashboard JSON
dashboard:
	python deploy/grafana/gen_dashboard.py

## clean: remove build artefacts
clean:
	rm -rf $(BUILD)

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
