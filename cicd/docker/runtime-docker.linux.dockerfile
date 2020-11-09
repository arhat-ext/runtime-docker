ARG ARCH=amd64

FROM ghcr.io/arhat-dev/builder-go:alpine as builder
FROM ghcr.io/arhat-dev/go:alpine-${ARCH}
ARG APP=runtime-docker

ENTRYPOINT [ "/runtime-docker" ]
