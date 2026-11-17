#!/usr/bin/env bash
# Runs appreg-inventory.sh against the mock az CLI in tests/mock and checks the reports.
# Needs only bash and jq - no Azure access.
# SPDX-License-Identifier: MIT
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../appreg-inventory.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PATH="$HERE/mock:$PATH"
export MOCK_CALLS="$WORK/calls"

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }
# has <file> <description> <tab-separated fields that must appear together on one line>
has() {
  local file="$1" desc="$2"; shift 2
  local pattern; pattern=$(IFS=$'\t'; echo "$*")
  if grep -qF -- "$pattern" "$file"; then ok "$desc"; else bad "$desc"; fi
}
lines() {  # lines <file> <description> <expected data rows>
  local n; n=$(($(wc -l < "$1") - 1))
  if [[ "$n" == "$3" ]]; then ok "$2"; else bad "$2 (got $n rows, expected $3)"; fi
}

echo "default mode (apps with client secrets)"
OUT="$WORK/out"
if bash "$SCRIPT" -o "$OUT" 2>"$WORK/log"; then ok "exits 0"; else bad "exits 0"; cat "$WORK/log"; fi
lines "$OUT/summary.tsv" "only apps with secrets are selected" 2
has "$OUT/summary.tsv" "terraform-deploy is CRITICAL with secret counts and lifetime" \
  CRITICAL terraform-deploy appA 2 1 2099-01-01T00:00:00Z 27394
has "$OUT/summary.tsv" "owners listed (user by UPN, SP by name)" "admin1@example.test, automation-sp"
has "$OUT/summary.tsv" "privileged Azure roles summarised" "Contributor@subscription x1; Owner@managementGroup x1"
has "$OUT/azure_rbac.tsv" "duplicate assignment (two sources, different case) counted once" \
  CRITICAL terraform-deploy appA direct Owner managementGroup
lines "$OUT/azure_rbac.tsv" "RBAC rows: MG + subscription (page 2) + group RG + root" 4
has "$OUT/azure_rbac.tsv" "role inherited through a group" "group: cloud-admins" Reader resourceGroup
has "$OUT/azure_rbac.tsv" "root scope assignment, role name from az role definition list" \
  CRITICAL billing-reader appC direct "User Access Administrator" root /
has "$OUT/entra_roles.tsv" "Entra role through a group (per-principal fallback)" \
  CRITICAL terraform-deploy appA "group: cloud-admins" "Application Administrator" active
has "$OUT/api_permissions.tsv" "Graph permission resolved to its name and rated" \
  CRITICAL terraform-deploy appA "Microsoft Graph" Application.ReadWrite.All
has "$OUT/api_permissions.tsv" "default access shown as such" LOW billing-reader appC "Microsoft Graph" "(default access)"
has "$OUT/sp_own_secrets.tsv" "SP with its own password credential listed" saml-app appS Application saml 1 2
if [[ -s "$WORK/calls" ]] && ! grep -q "roleEligibilitySchedules" "$WORK/calls"; then ok "PIM eligibility is not queried"; else bad "PIM eligibility is not queried"; fi
if grep -rqi '"hint"' "$OUT"; then bad "no secret hints in the output"; else ok "no secret hints in the output"; fi
perm=$(stat -c %a "$OUT/summary.tsv" 2>/dev/null || stat -f %Lp "$OUT/summary.tsv")
if [[ "$perm" == 600 ]]; then ok "reports readable by owner only"; else bad "reports readable by owner only (mode $perm)"; fi

echo "-A (all apps)"
bash "$SCRIPT" -A -o "$WORK/all" 2>/dev/null
lines "$WORK/all/summary.tsv" "all 3 apps included" 3
has "$WORK/all/summary.tsv" "app without credentials rated LOW" LOW no-secret-app appB 0

echo "-a (single app)"
bash "$SCRIPT" -a 12345678-1234-1234-1234-123456789abc -o "$WORK/one" 2>/dev/null
lines "$WORK/one/summary.tsv" "one app" 1
if [[ ! -e "$WORK/one/sp_own_secrets.tsv" ]]; then ok "no tenant-wide SP report in -a mode"; else bad "no tenant-wide SP report in -a mode"; fi

echo "Windows (Git Bash: CRLF output from az and jq, MSYS path rewriting)"
REAL_JQ=$(type -P jq) PATH="$HERE/mock-windows:$PATH" bash "$SCRIPT" -o "$WORK/win" 2>"$WORK/winlog"
if grep -q "Bad Request" "$WORK/winlog"; then
  bad "no 'Bad Request' errors"; grep -m3 "Bad Request" "$WORK/winlog"
else ok "no 'Bad Request' errors"; fi
for f in summary azure_rbac entra_roles api_permissions sp_own_secrets; do
  if cmp -s "$OUT/$f.tsv" "$WORK/win/$f.tsv"; then ok "$f.tsv same as on Linux"; else bad "$f.tsv same as on Linux"; fi
done

echo "appreg-summary.sh"
SUM="$HERE/../appreg-summary.sh"
bash "$SUM" "$WORK/all" > "$WORK/sum.md" 2>"$WORK/sumlog" && ok "summary exits 0" || { bad "summary exits 0"; cat "$WORK/sumlog"; }
if grep -qF "| CRITICAL | 2 | 2 | 1 | 1 |" "$WORK/sum.md"; then ok "risk table counts"; else bad "risk table counts"; fi
if grep -qF "Valid secrets in total: **2**" "$WORK/sum.md"; then ok "valid secrets counted"; else bad "valid secrets counted"; fi
if grep -qF "lifetime over 1 year: **1**, over 2 years: **1**" "$WORK/sum.md"; then ok "secret lifetimes"; else bad "secret lifetimes"; fi
if grep -qF "root or management-group scope: **2**" "$WORK/sum.md"; then ok "CRITICAL reasons"; else bad "CRITICAL reasons"; fi
if grep -qF "| Owner @ managementGroup | 1 |" "$WORK/sum.md"; then ok "top Azure roles"; else bad "top Azure roles"; fi
if ! grep -qE "terraform-deploy|billing-reader|appA|admin1@" "$WORK/sum.md"; then ok "no names without -n"; else bad "no names without -n"; fi
bash "$SUM" -n "$WORK/all" > "$WORK/sumn.md" 2>/dev/null
if grep -qF "| CRITICAL | terraform-deploy | appA |" "$WORK/sumn.md"; then ok "-n lists CRITICAL apps"; else bad "-n lists CRITICAL apps"; fi
if bash "$SUM" -n -d 40000 "$WORK/all" | grep -qF "| 2099-01-01T00:00:00Z | terraform-deploy | CRITICAL |"; then ok "-d widens the expiry window"; else bad "-d widens the expiry window"; fi
if ! bash "$SUM" "$WORK/nonexistent" >/dev/null 2>&1; then ok "rejects a folder without inventory"; else bad "rejects a folder without inventory"; fi

echo "argument checks"
if ! bash "$SCRIPT" -a not-a-guid >/dev/null 2>&1; then ok "rejects a malformed app ID"; else bad "rejects a malformed app ID"; fi
if bash "$SCRIPT" -h | grep -q "READ-ONLY inventory"; then ok "-h prints help"; else bad "-h prints help"; fi

echo
echo "$pass passed, $fail failed"
((fail == 0))
