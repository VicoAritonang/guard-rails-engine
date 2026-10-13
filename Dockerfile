# Multi-stage build producing a distroless, non-root image.
#
# The engine is a security control in the request path, so the container gets
# the smallest attack surface Go makes practical: static binary, no shell, no
# package manager, non-root user, read-only root filesystem (set at runtime).

# ---- build ------------------------------------------------------------------
FROM golang:1.25-alpine AS build

ARG VERSION=dev
WORKDIR /src

# Dependencies first: this layer is cached unless go.mod/go.sum change, which
# turns a code-only rebuild from minutes into seconds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off makes the binary static, which is what lets the final stage be
# distroless/static rather than a glibc base.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/grctl ./cmd/grctl

# Run the suite inside the build so a broken image cannot be produced at all.
RUN go test ./... > /dev/null

# The log directory ships in the image, owned by the nonroot user, so a named
# volume mounted over it inherits that ownership. A root-owned volume would make
# the log file unwritable and the gateway would refuse to start.
RUN mkdir -p /out/log

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

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

# The binary serves /healthz; orchestrators should probe that rather than
# relying on a HEALTHCHECK, since distroless has no shell to run one.
ENTRYPOINT ["/usr/local/bin/server"]
