# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies are copied first so the module cache layer survives source edits.
COPY go.mod ./
RUN go mod download

COPY . .

# CGO is disabled deliberately: the SQLite driver is pure Go, so the result is a
# fully static binary that runs on a distroless base with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/clerk ./cmd/clerk

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/clerk /clerk

# The SQLite database and the RS256 signing key must both outlive the container.
VOLUME ["/data", "/keys"]

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/clerk"]
