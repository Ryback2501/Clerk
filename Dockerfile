# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies are copied first so the module cache layer survives source edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is disabled deliberately: the SQLite driver is pure Go, so the result is a
# fully static binary that runs on a distroless base with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/clerk ./cmd/clerk

# The runtime stage is distroless and has no shell, so the state directories are
# created here and copied in with the right ownership below.
RUN mkdir -p /out/data /out/keys

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/clerk /clerk

# Owned by the nonroot user (uid 65532) the container runs as. Without this the
# directories land root-owned and the process cannot create its database or
# persist a signing key. Docker propagates this ownership into a fresh named
# volume; a bind mount takes its ownership from the host instead, so a host
# directory mounted there must be writable by the same uid.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/keys /keys

# The SQLite database and the RS256 signing key must both outlive the container.
VOLUME ["/data", "/keys"]

EXPOSE 8080
USER nonroot:nonroot

# Exec form: the runtime image has no shell, so a shell-form check could never
# run. The binary checks its own /health endpoint.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["/clerk", "-healthcheck"]

ENTRYPOINT ["/clerk"]
