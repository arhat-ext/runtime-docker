ARG ARCH=amd64

# we do not use cgo so we can build on alpine and copy it to debian
FROM ghcr.io/arhat-dev/builder-go:alpine as builder
FROM ghcr.io/arhat-dev/go:debian-${ARCH}
ARG APP=runtime-docker

ENTRYPOINT [ "/runtime-docker" ]
