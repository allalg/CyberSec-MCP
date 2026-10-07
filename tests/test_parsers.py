"""Unit tests for tool output parsers."""

from __future__ import annotations

from server.parsers.dns_parser import parse_dns_output
from server.parsers.nmap_parser import parse_nmap_output
from server.parsers.web_parser import parse_directory_scan_output, parse_http_probe_output
from server.parsers.whois_parser import parse_whois_output

# ── Sample Fixtures ────────────────────────────────────────────────────────

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - target" start="1696700000">
<host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.52"/>
        </port>
    </ports>
</host>
</nmaprun>
"""

SAMPLE_NMAP_TEXT = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-07 12:00 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0010s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    Apache httpd 2.4.52
"""

SAMPLE_DIG_OUTPUT = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;lab.local.			IN	A

;; ANSWER SECTION:
lab.local.		300	IN	A	172.28.0.10
lab.local.		300	IN	A	172.28.0.11

;; Query time: 12 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
"""

SAMPLE_WHOIS_OUTPUT = """
   Domain Name: LAB.LOCAL
   Registry Domain ID: 1234567_DOMAIN_LOCAL
   Registrar: Lab Registrar Inc.
   Creation Date: 2020-01-15T00:00:00Z
   Registry Expiry Date: 2028-01-15T00:00:00Z
   Name Server: NS1.LAB.LOCAL
   Name Server: NS2.LAB.LOCAL
   Registrant Organization: CyberSec Lab Organization
   Registrant Country: US
   Admin Email: security@lab.local
"""

SAMPLE_CURL_OUTPUT = """HTTP/1.1 200 OK\r
Date: Wed, 07 Oct 2026 12:00:00 GMT\r
Server: Apache/2.4.52 (Ubuntu)\r
Content-Type: text/html; charset=UTF-8\r
Content-Length: 123\r
X-Frame-Options: SAMEORIGIN\r
\r
<html><body><h1>Lab Target Web</h1></body></html>"""

SAMPLE_GOBUSTER_OUTPUT = """
/admin                (Status: 301) [Size: 178] [--> http://lab.local/admin/]
/login                (Status: 200) [Size: 2450]
/api                  (Status: 200) [Size: 52]
/secret_backup        (Status: 403) [Size: 280]
"""


def test_nmap_xml_parser():
    findings, summary = parse_nmap_output(SAMPLE_NMAP_XML)
    assert len(findings) == 2
    assert summary["open_ports"] == 2

    ssh_finding = findings[0]
    assert ssh_finding["port"] == 22
    assert ssh_finding["protocol"] == "tcp"
    assert ssh_finding["state"] == "open"
    assert ssh_finding["service"] == "ssh"
    assert ssh_finding["version"] == "8.9p1"

    http_finding = findings[1]
    assert http_finding["port"] == 80
    assert http_finding["service"] == "http"


def test_nmap_text_parser():
    findings, summary = parse_nmap_output(SAMPLE_NMAP_TEXT)
    assert len(findings) == 2
    assert summary["open_ports"] == 2
    assert findings[0]["port"] == 22
    assert findings[1]["port"] == 80


def test_dns_parser():
    records, summary = parse_dns_output(SAMPLE_DIG_OUTPUT)
    assert len(records) == 2
    assert summary["answer_count"] == 2
    assert summary["query_time_ms"] == 12

    rec1 = records[0]
    assert rec1["name"] == "lab.local"
    assert rec1["type"] == "A"
    assert rec1["value"] == "172.28.0.10"
    assert rec1["ttl"] == 300


def test_whois_parser():
    findings, summary = parse_whois_output(SAMPLE_WHOIS_OUTPUT)
    assert len(findings) == 1
    f = findings[0]
    assert f["domain"] == "LAB.LOCAL"
    assert f["registrar"] == "Lab Registrar Inc."
    assert "ns1.lab.local" in f["nameservers"]
    assert "security@lab.local" in f["emails"]


def test_http_probe_parser():
    findings, summary = parse_http_probe_output(SAMPLE_CURL_OUTPUT)
    assert len(findings) == 1
    f = findings[0]
    assert f["status_code"] == 200
    assert f["http_version"] == "HTTP/1.1"
    assert f["server"] == "Apache/2.4.52 (Ubuntu)"
    assert f["security_headers"]["x-frame-options"] == "SAMEORIGIN"
    assert "strict-transport-security" in f["missing_security_headers"]


def test_directory_scan_parser():
    findings, summary = parse_directory_scan_output(SAMPLE_GOBUSTER_OUTPUT)
    assert len(findings) == 4
    assert summary["total_paths_found"] == 4

    paths = [f["path"] for f in findings]
    assert "/admin" in paths
    assert "/login" in paths
    assert "/api" in paths
    assert "/secret_backup" in paths
