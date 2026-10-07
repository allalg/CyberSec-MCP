# Web & DNS Tools Sandbox Container
# Alpine image with curl, bind-tools (dig, nslookup), whois, and gobuster

FROM alpine:3.19

RUN apk add --no-cache curl bind-tools whois

# Download and install precompiled gobuster release binary
ADD https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz /tmp/gobuster.tar.gz
RUN tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster && \
    rm /tmp/gobuster.tar.gz && \
    chmod +x /usr/local/bin/gobuster && \
    mkdir -p /usr/share/wordlists/dirb && \
    printf "admin\nlogin\napi\nrobots.txt\ndashboard\nindex.html\n" > /usr/share/wordlists/dirb/common.txt && \
    adduser -D -s /bin/sh -u 1000 scanner

USER scanner

WORKDIR /home/scanner
