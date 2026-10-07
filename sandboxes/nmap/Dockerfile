# Nmap Sandbox Container
# Minimal Alpine image with nmap and nmap-scripts, unprivileged user

FROM alpine:3.19

RUN apk add --no-cache nmap nmap-scripts && \
    adduser -D -s /bin/sh -u 1000 scanner

USER scanner

ENTRYPOINT ["nmap"]
