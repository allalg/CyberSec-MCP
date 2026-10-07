# Analysis Tools Sandbox Container
# Isolated container for static artifact analysis (hashing, file inspection)
# Runs with network: none

FROM alpine:3.19

RUN apk add --no-cache coreutils file && \
    adduser -D -s /bin/sh -u 1000 analyzer

USER analyzer

WORKDIR /data
