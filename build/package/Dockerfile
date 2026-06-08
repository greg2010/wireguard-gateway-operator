# Build stage: compile the gateway-link binary statically with a shared build cache.
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o /out/ ./cmd/...

# Link runtime stage: alpine plus the CLIs gateway-link shells out to (ip, wg, nft).
FROM alpine:3.21 AS link

RUN apk add --no-cache iproute2 wireguard-tools nftables

COPY --from=builder /out/gateway-link /usr/local/bin/

# Default to a numeric non-root identity so kubelet can verify runAsNonRoot
# without a runAsUser override. The link workload re-grants NET_ADMIN via the
# pod securityContext; the image itself stays unprivileged.
RUN addgroup -g 10001 gateway \
    && adduser -D -u 10001 -G gateway gateway
USER 10001:10001

# No ENTRYPOINT: the workload sets its own command (gateway-link).

# Operator runtime stage: the manager only talks to the API server, so it needs
# no extra CLIs beyond TLS roots. Build with --target operator.
FROM alpine:3.21 AS operator

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/gateway-operator /usr/local/bin/

# Numeric non-root identity: kubelet's runAsNonRoot check cannot resolve a named
# user, so the UID must be numeric in the image.
RUN addgroup -g 10001 gateway \
    && adduser -D -u 10001 -G gateway gateway
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/gateway-operator"]
