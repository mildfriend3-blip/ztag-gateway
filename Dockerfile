# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Multi-stage build. The runtime image is distroless and runs as a non-root
# user with a read-only root filesystem, so a compromise of the proxy process
# gains no shell, no package manager and no writable filesystem.
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS build

WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux

# Dependencies first for layer caching. The gateway has no third-party modules,
# so this is just the module file.
COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/ztag-proxy ./cmd/proxy && \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/ztag-logworker ./cmd/logworker && \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/ztag-echo ./cmd/echo && \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/ztag-tokengen ./cmd/tokengen && \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/ztag-loadgen ./cmd/loadgen

# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/ztag-proxy /usr/local/bin/ztag-proxy
COPY --from=build /out/ztag-logworker /usr/local/bin/ztag-logworker
COPY --from=build /out/ztag-echo /usr/local/bin/ztag-echo
COPY --from=build /out/ztag-tokengen /usr/local/bin/ztag-tokengen
COPY --from=build /out/ztag-loadgen /usr/local/bin/ztag-loadgen

USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/ztag-proxy"]
