# Multi-stage build producing a distroless, non-root image.
#
# The engine is a security control in the request path, so the container gets
# the smallest attack surface Go makes practical: static binary, no shell, no
# package manager, non-root user, read-only root filesystem (set at runtime).
#
# Base images are pinned by digest so a build cannot silently change underneath
# a release; Dependabot proposes the updates.

# ---- build ------------------------------------------------------------------
# The build stage runs on the builder's own architecture and cross-compiles. An
# arm64 image then needs no emulation, which would take far longer than the
# build itself.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
# The release workflow sets this to false: it has already run the suite, once,
# rather than once per architecture.
ARG RUN_TESTS=true
WORKDIR /src

# Dependencies first: this layer is cached unless go.mod/go.sum change, which
# turns a code-only rebuild from minutes into seconds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off makes the binary static, which is what lets the final stage be
# distroless/static rather than a glibc base.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/grctl ./cmd/grctl

# Run the suite inside the build so a broken image cannot be produced at all.
RUN if [ "$RUN_TESTS" = "true" ]; then go test ./...; fi

# The log directory ships in the image, owned by the nonroot user, so a named
# volume mounted over it inherits that ownership. A root-owned volume would make
# the log file unwritable and the gateway would refuse to start.
RUN mkdir -p /out/log

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
LABEL org.opencontainers.image.title="guard-rails-engine" \
      org.opencontainers.image.description="AI guardrails gateway: prompt, tool and output controls with an evaluation harness" \
      org.opencontainers.image.source="https://github.com/VicoAritonang/guard-rails-engine" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/server /usr/local/bin/server
COPY --from=build /out/grctl  /usr/local/bin/grctl
COPY --from=build /src/config/policies /etc/guardrails/policies
COPY --from=build /src/config/models.yaml /etc/guardrails/models.yaml
COPY --from=build /src/config/mcp.yaml /etc/guardrails/mcp.yaml
COPY --from=build /src/testdata/eval /usr/share/guardrails/eval
COPY --from=build /src/config/pricing.yaml /etc/guardrails/pricing.yaml
COPY --from=build --chown=65532:65532 /out/log /var/log/guardrails

USER nonroot:nonroot
EXPOSE 8080

ENV GUARDRAILS_ADDR=:8080 \
    GUARDRAILS_PROVIDER=mock \
    GUARDRAILS_LOG_FORMAT=json

# Distroless has no shell or curl, so the probe is a subcommand of grctl.
# Kubernetes ignores this and uses the probes in deploy/kubernetes.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/grctl", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/server"]
