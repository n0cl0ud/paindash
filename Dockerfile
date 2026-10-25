# syntax=docker/dockerfile:1
# Every base image is pinned by digest. Scanners are pinned to releases at
# least two weeks old (a compromised scanner sees every image we run) and
# built from source: see tools/.
# Multi-arch: the build stages run on the build platform and Go cross-compiles
# for the target one (no emulation).

FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4 AS build
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# ECR credential helper, so syft can pull from ECR with the pod's IAM role.
# A cross-compiled go install lands in $GOPATH/bin/<os>_<arch>/.
RUN go install -trimpath -ldflags="-s -w" \
    github.com/awslabs/amazon-ecr-credential-helper/ecr-login/cli/docker-credential-ecr-login@v0.12.0 && \
    mkdir -p /out && cp "$(find /go/bin -name docker-credential-ecr-login)" /out/
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN go build -trimpath -ldflags="-s -w" -o /out/paindash ./cmd/paindash

# syft and grype built from their pinned sources with our patched Go toolchain
# and dependency overrides (tools/*/go.mod), instead of the release binaries.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4 AS scanners
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
WORKDIR /src/tools
COPY tools/ ./
RUN for t in syft grype; do \
      cd "/src/tools/$t" && \
      v=$(go list -m -f '{{.Version}}' "github.com/anchore/$t") && \
      go build -mod=readonly -trimpath -ldflags="-s -w -X main.version=$v" \
        -o "/out/$t" "github.com/anchore/$t/cmd/$t" || exit 1; \
    done

FROM alpine:3.24@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35
# The CA bundle Go reads (/etc/ssl/certs/ca-certificates.crt) ships with the
# pinned base image: nothing is fetched at build time.
RUN adduser -D -u 10001 paindash
COPY --from=scanners /out/syft /out/grype /usr/local/bin/
COPY --from=build /out/docker-credential-ecr-login /usr/local/bin/
COPY --from=build /out/paindash /usr/local/bin/paindash
USER 10001
ENV GRYPE_DB_CACHE_DIR=/var/cache/paindash/grype \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/paindash"]
