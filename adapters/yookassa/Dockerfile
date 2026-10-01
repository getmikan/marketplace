# syntax=docker/dockerfile:1.7
# Build from the repository root:
#   docker buildx build --platform linux/amd64,linux/arm64 -f adapters/yookassa/Dockerfile .
# Go cross-compiles on the build platform; only the final stage is the target's.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY internal/ internal/
COPY adapters/yookassa/ adapters/yookassa/
# Filled in by BuildKit for each platform. A default here would win over it and put
# amd64 binaries into the arm64 image.
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/adapter ./adapters/yookassa
# The binary must be the image's own architecture: the ELF machine field says so.
RUN case "$TARGETARCH" in amd64) want="3e 00" ;; arm64) want="b7 00" ;; *) want="" ;; esac; \
    got=$(od -A n -t x1 -j 18 -N 2 /out/adapter | tr -s " " | sed "s/^ //"); \
    if [ -n "$want" ] && [ "$got" != "$want" ]; then echo "the adapter is not built for $TARGETARCH (ELF machine $got)"; exit 1; fi

# Static binary and CA certificates, no shell; runs as 65532 and writes no files, so a
# read-only root file system is fine.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/adapter /adapter
USER 65532:65532
ENTRYPOINT ["/adapter"]
