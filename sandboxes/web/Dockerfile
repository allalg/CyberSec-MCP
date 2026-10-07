# Web & DNS Tools Sandbox Container
# Alpine image with curl, bind-tools (dig, nslookup), whois, gobuster

FROM alpine:3.19

RUN apk add --no-cache curl bind-tools whois gobuster && \
    adduser -D -s /bin/sh -u 1000 scanner

USER scanner

WORKDIR /home/scanner
