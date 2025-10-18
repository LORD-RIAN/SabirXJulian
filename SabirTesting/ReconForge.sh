#!/usr/bin/env bash
set -euo pipefail

# Usage: ./ReconForge.sh example.com
# Requirements: subfinder, dig, python3, nmap
#
# Descriptionn:
# ReconForge — finds subdomains, drops CDN junk, and runs Nmap on the real hosts.
#
# Workflow:
#  1) creates directory ./<target> and places everything inside
#  2) subfinder -> ./<target>/<target>_subdomains.txt
#  3) resolve A only -> ./<target>/<target>_iptemp.txt
#  4) dedupe -> ./<target>/<target>_ipunque.txt
#  5) filter Cloudflare + Vercel CIDRs -> ./<target>/<target>_ip.txt (final)
#  6) write removed/blocked IPs to ./<target>/<target>_blocked_ips.txt
#  7) remove intermediate files (_iptemp, _ipunque)
#  8) run nmap -A -T4 -v -p- -iL <final> -oA <target>_nmap (outputs inside target dir)
#
# Filenames inside folder:
#   <target>_subdomains.txt
#   <target>_iptemp.txt
#   <target>_ipunque.txt
#   <target>_blocked_ips.txt
#   <target>_ip.txt
#   <target>_nmap.nmap/.gnmap/.xml
#

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target-domain>" >&2
  exit 2
fi

target="$1"
dir="${target}"
mkdir -p "$dir"

sub_file="${dir}/${target}_subdomains.txt"
iptemp="${dir}/${target}_iptemp.txt"
ipunque="${dir}/${target}_ipunque.txt"
blocked="${dir}/${target}_blocked_ips.txt"
final="${dir}/${target}_ip.txt"
nmap_base="${dir}/${target}_nmap"

# Cloudflare CIDRs (as you provided)
CF_CIDRS=(
  "173.245.48.0/20"
  "103.21.244.0/22"
  "103.22.200.0/22"
  "103.31.4.0/22"
  "141.101.64.0/18"
  "108.162.192.0/18"
  "190.93.240.0/20"
  "188.114.96.0/20"
  "197.234.240.0/22"
  "198.41.128.0/17"
  "162.158.0.0/15"
  "104.16.0.0/13"
  "104.24.0.0/14"
  "172.64.0.0/13"
  "131.0.72.0/22"
)

# Vercel CIDRs (as you provided)
VERCEL_CIDRS=(
  "64.29.17.0/24"
  "64.239.109.0/24"
  "64.239.123.0/24"
  "66.33.60.0/24"
  "76.76.21.0/24"
  "198.169.1.0/24"
  "198.169.2.0/24"
  "216.150.1.0/24"
  "216.150.16.0/24"
  "216.198.79.0/24"
  "216.230.84.0/24"
  "216.230.86.0/24"
  "216.198.79.80/29"
)

# prepare/clear files
: > "$iptemp"
: > "$ipunque"
: > "$blocked"
: > "$final"

ipv4_re='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

echo "[*] Running subfinder for $target ..."
subfinder -all -silent -d "$target" > "$sub_file" || {
  echo "subfinder failed or returned non-zero. Check installation/flags." >&2
  exit 3
}

echo "[*] Resolving A records (IPv4 only) for subdomains from $sub_file ..."
while IFS= read -r sub || [[ -n "${sub:-}" ]]; do
  sub="${sub##[[:space:]]}"
  sub="${sub%%[[:space:]]}"
  [[ -z "$sub" ]] && continue

  a_ips=$(dig +short A "$sub" 2>/dev/null || true)

  while IFS= read -r line; do
    [[ -z "${line:-}" ]] && continue
    if [[ $line =~ $ipv4_re ]]; then
      echo "$line" >> "$iptemp"
    fi
  done <<< "$a_ips"

done < "$sub_file"

raw_count=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$iptemp" | wc -l || true)

# dedupe into ipunque
sort -u "$iptemp" > "$ipunque" || true
pre_cf_count=$(wc -l < "$ipunque" || true)

echo "[*] Collected IPs:"
echo "   raw (with duplicates) -> $iptemp (count: $raw_count)"
echo "   deduped pre-block     -> $ipunque (count: $pre_cf_count)"

# Build python literal lists for CF and Vercel (safe quoting)
cf_literal="$(printf "'%s', " "${CF_CIDRS[@]}" | sed 's/, $//')"
vercel_literal="$(printf "'%s', " "${VERCEL_CIDRS[@]}" | sed 's/, $//')"

# Use python to filter IPs reliably by CIDR membership and record which block removed an ip
python3 - <<PY
import ipaddress

cf_cidrs = [${cf_literal}]
vercel_cidrs = [${vercel_literal}]

cf_nets = [ipaddress.ip_network(c) for c in cf_cidrs]
vercel_nets = [ipaddress.ip_network(c) for c in vercel_cidrs]

infile = "${ipunque}"
outfile = "${final}"
blocked_file = "${blocked}"

try:
    with open(infile, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    ips = []

kept = []
blocked_entries = []  # tuples (ip, reason)

for ip in ips:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        continue
    removed = False
    for net in cf_nets:
        if a in net:
            blocked_entries.append((ip, "cloudflare"))
            removed = True
            break
    if removed:
        continue
    for net in vercel_nets:
        if a in net:
            blocked_entries.append((ip, "vercel"))
            removed = True
            break
    if not removed:
        kept.append(ip)

with open(outfile, 'w') as f:
    for ip in kept:
        f.write(ip + "\\n")

with open(blocked_file, 'w') as f:
    for ip, why in blocked_entries:
        f.write(f"{ip}\\t{why}\\n")

# print counts for logging (these will appear in terminal)
print(f"PY_FINAL_COUNT:{len(kept)}")
print(f"PY_BLOCKED_COUNT:{len(blocked_entries)}")
PY

# read python printed counts
py_final_count=$(python3 - <<PY
# extract printed values from above run by re-reading blocked/final file sizes
import sys, os
final="${final}"
blocked="${blocked}"
fcount = 0
bcount = 0
try:
    with open(final,'r') as f:
        fcount = sum(1 for _ in f)
except:
    fcount = 0
try:
    with open(blocked,'r') as f:
        bcount = sum(1 for _ in f)
except:
    bcount = 0
print(fcount)
print(bcount)
PY
)

# py_final_count contains two numbers separated by newline
final_count=$(echo "$py_final_count" | sed -n '1p' || true)
blocked_count=$(echo "$py_final_count" | sed -n '2p' || true)

echo "[*] After filtering Cloudflare + Vercel:"
echo "   blocked (written)      -> $blocked (count: $blocked_count)"
echo "   final unique IPs       -> $final (count: $final_count)"

# remove intermediate files as requested
rm -f "$iptemp" "$ipunque"
echo "[*] Removed temporary files: $iptemp , $ipunque"

# if no IPs left, skip nmap
if [[ "${final_count:-0}" -eq 0 ]]; then
  echo "[!] No IPs left after filtering. Skipping nmap."
  exit 0
fi

echo "[*] Running nmap against IPs in $final ..."
# ensure outputs go inside directory by using nmap_base which has dir prefix
nmap -A -T4 -v -p- -iL "$final" -oA "$nmap_base"
nmap_status=$?
if [[ $nmap_status -ne 0 ]]; then
  echo "[!] nmap exited with status $nmap_status (non-zero). Check output files." >&2
else
  echo "[*] nmap finished successfully."
fi
echo "  nmap outputs -> ${nmap_base}.nmap   ${nmap_base}.gnmap   ${nmap_base}.xml"

exit $nmap_status