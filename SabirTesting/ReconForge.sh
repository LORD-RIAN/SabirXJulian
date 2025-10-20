#!/usr/bin/env bash
set -euo pipefail

# ReconForge.sh
# Usage: ./ReconForge.sh <target-domain>
# Requirements: subfinder, dig, python3, nmap
# Behavior:
#  - creates ./<target>/ and stores all outputs there
#  - expects a blocklist file at ./reconforge_blocked_cidrs.txt or /mnt/data/reconforge_blocked_cidrs.txt
#  - enumerates subdomains, resolves only A records, filters blocked CIDRs, runs nmap on remaining IPs

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target-domain>" >&2
  exit 2
fi

target="$1"
dir="${target}"
mkdir -p "$dir"

# files inside target dir
sub_file="${dir}/${target}_subdomains.txt"
iptemp="${dir}/${target}_iptemp.txt"
ipunque="${dir}/${target}_ipunque.txt"
blocked="${dir}/${target}_blocked_ips.txt"
final="${dir}/${target}_ip.txt"
nmap_base="${dir}/${target}_nmap"

# where to look for the combined blocklist
BLOCKLIST_LOCAL="./reconforge_blocked_cidrs.txt"
BLOCKLIST_ALT="/mnt/data/reconforge_blocked_cidrs.txt"

if [[ -f "$BLOCKLIST_LOCAL" ]]; then
  BLOCKLIST_FILE="$BLOCKLIST_LOCAL"
elif [[ -f "$BLOCKLIST_ALT" ]]; then
  BLOCKLIST_FILE="$BLOCKLIST_ALT"
else
  echo "[!] Blocklist file not found. Create $BLOCKLIST_LOCAL or place file at $BLOCKLIST_ALT" >&2
  exit 3
fi

echo "[*] Using blocklist: $BLOCKLIST_FILE"

# ensure required commands exist
for cmd in subfinder dig python3 nmap; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Required command not found: $cmd" >&2
    exit 4
  fi
done

# clear/prepare files
: > "$iptemp"
: > "$ipunque"
: > "$blocked"
: > "$final"

ipv4_re='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

echo "[*] Running subfinder for $target ..."
subfinder -all -silent -d "$target" > "$sub_file" || {
  echo "[!] subfinder failed or returned non-zero. Check installation/flags." >&2
  exit 5
}

echo "[*] Resolving A records (IPv4 only) for subdomains listed in $sub_file ..."
while IFS= read -r sub || [[ -n "${sub:-}" ]]; do
  # trim whitespace
  sub="${sub##[[:space:]]}"
  sub="${sub%%[[:space:]]}"
  [[ -z "$sub" ]] && continue

  # query A records only
  a_ips=$(dig +short A "$sub" 2>/dev/null || true)

  # append valid IPv4-looking lines to iptemp
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
pre_block_count=$(wc -l < "$ipunque" || true)

echo "[*] Collected IPs:"
echo "   raw (with duplicates) -> $iptemp (count: $raw_count)"
echo "   deduped pre-block     -> $ipunque (count: $pre_block_count)"

# Use python to filter ipunque against the blocklist file and write final + blocked files.
# Python will:
#  - read blocklist CIDRs from $BLOCKLIST_FILE
#  - read ips from $ipunque
#  - write kept IPs to $final
#  - write blocked IPs with reason to $blocked (reason = the CIDR matched)
python3 - "$BLOCKLIST_FILE" "$ipunque" "$final" "$blocked" <<'PYCODE'
import sys, ipaddress

blocklist_path = sys.argv[1]
in_ips_path = sys.argv[2]
out_kept = sys.argv[3]
out_blocked = sys.argv[4]

# read blocklist (ignore blank/comment lines)
blocked_cidrs = []
try:
    with open(blocklist_path, 'r') as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            blocked_cidrs.append(ln)
except FileNotFoundError:
    print(f"[python] Blocklist file not found: {blocklist_path}", file=sys.stderr)
    sys.exit(2)

# compile networks
nets = []
for c in blocked_cidrs:
    try:
        nets.append(ipaddress.ip_network(c))
    except Exception as e:
        print(f"[python] Skipping invalid CIDR '{c}': {e}", file=sys.stderr)

# read ips
ips = []
try:
    with open(in_ips_path, 'r') as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            ips.append(ln)
except FileNotFoundError:
    ips = []

kept = []
blocked = []  # tuples (ip, matched_cidr)

for ip in ips:
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        # ignore invalid IP-like entries
        continue
    matched = False
    for net in nets:
        if a in net:
            blocked.append((ip, str(net.with_prefixlen)))
            matched = True
            break
    if not matched:
        kept.append(ip)

# write outputs
with open(out_kept, 'w') as f:
    for ip in kept:
        f.write(ip + "\n")

with open(out_blocked, 'w') as f:
    for ip, why in blocked:
        f.write(f"{ip}\t{why}\n")

# print summary to stdout for the bash script
print(f"PY_KEEP:{len(kept)}")
print(f"PY_BLOCKED:{len(blocked)}")
PYCODE

# capture python-derived counts (re-read files)
final_count=$(wc -l < "$final" 2>/dev/null || echo 0)
blocked_count=$(wc -l < "$blocked" 2>/dev/null || echo 0)

echo "[*] After filtering against blocklist ($BLOCKLIST_FILE):"
echo "   blocked (written)      -> $blocked (count: $blocked_count)"
echo "   final unique IPs       -> $final (count: $final_count)"

# remove intermediate files
rm -f "$iptemp" "$ipunque"
echo "[*] Removed temporary files: $iptemp , $ipunque"

# if no IPs left, skip nmap
if [[ "${final_count:-0}" -eq 0 ]]; then
  echo "[!] No IPs left after filtering. Skipping nmap."
  exit 0
fi

echo "[*] Running nmap against IPs in $final ..."
nmap -A -T4 -v -p- -iL "$final" -oA "$nmap_base"
nmap_status=$?
if [[ $nmap_status -ne 0 ]]; then
  echo "[!] nmap exited with status $nmap_status (non-zero). Check output files." >&2
else
  echo "[*] nmap finished successfully."
fi

echo "  nmap outputs -> ${nmap_base}.nmap   ${nmap_base}.gnmap   ${nmap_base}.xml"
exit $nmap_status
