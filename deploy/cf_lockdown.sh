#!/bin/bash
# Lock incoming :80 + :443 to Cloudflare IP ranges only.
# SSH (22) stays open from anywhere so we don't brick the box.
# Idempotent: re-running rebuilds the rules from scratch.

set -e

# Wipe any previous CF rules so a re-run replaces (not appends) them.
# We tag every CF rule with comment 'cf-*' for easy bulk delete.
echo "> resetting ufw to a clean state..."
ufw --force reset >/dev/null

# Allow SSH FIRST, before any deny policy gets set.
# Without this, ufw enable closes our session.
ufw allow 22/tcp comment 'ssh'

# Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4)
for cidr in 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 \
            103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 \
            190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 \
            198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
            104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
  ufw allow from $cidr to any port 80 proto tcp comment 'cf-v4'
  ufw allow from $cidr to any port 443 proto tcp comment 'cf-v4'
done

# Cloudflare IPv6 ranges (https://www.cloudflare.com/ips-v6)
for cidr in 2400:cb00::/32 2606:4700::/32 2803:f800::/32 \
            2405:b500::/32 2405:8100::/32 2a06:98c0::/29 \
            2c0f:f248::/32; do
  ufw allow from $cidr to any port 80 proto tcp comment 'cf-v6'
  ufw allow from $cidr to any port 443 proto tcp comment 'cf-v6'
done

# Defaults: block everything else inbound, allow all outbound.
ufw default deny incoming
ufw default allow outgoing

# Enable (non-interactive so it doesn't prompt about SSH disruption).
ufw --force enable

echo "> done. final ruleset:"
ufw status verbose | head -60
