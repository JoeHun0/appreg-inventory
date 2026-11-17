#!/usr/bin/env bash
# appreg-summary.sh - turns an appreg-inventory output folder into two files:
#
#   appreg-report.md     counts only, no app names, IDs or owners - safe to put into a report:
#                 risk levels, secret validity and lifetime, ownership, why apps are
#                 CRITICAL, the most common privileged roles and permissions, cleanup
#   appreg-worklist.csv  one row per thing to fix, with app names, details and what to
#                 do - internal. item_id (category:appId) stays the same between runs, so
#                 the file can feed a tracking spreadsheet (Excel: Data > From Text/CSV)
#                 and statuses kept there survive a refresh.
#
# Usage:
#   ./appreg-summary.sh <output folder>          writes both files into that folder
#   ./appreg-summary.sh -o <dir> <output folder> writes them into <dir> instead
#   ./appreg-summary.sh -d 60 <output folder>    "expires soon" window in days (default 30)
#   ./appreg-summary.sh -s ';' <output folder>   CSV separator (default ","; use ";" if Excel
#                                                with a Hungarian or German locale opens it)
#
# Reads raw/model.jsonl and raw/apps.jsonl from the folder. Needs only jq; no Azure access.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/appreg-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

DAYS=30
SEP=","
OUT=""
while getopts ":d:s:o:h" opt; do
  case "$opt" in
    d) DAYS="$OPTARG" ;;
    s) SEP="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
(($# == 1)) || die "give one appreg-inventory output folder (-h for help)"
[[ "$DAYS" =~ ^[0-9]+$ ]] || die "-d needs a number of days"
[[ "$SEP" == "," || "$SEP" == ";" || "$SEP" == $'\t' ]] || die "-s must be , or ; or a tab"
DIR="$1"
for f in model apps; do
  [[ -s "$DIR/raw/$f.jsonl" ]] || die "$DIR/raw/$f.jsonl not found - is this an appreg-inventory output folder?"
done
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
jq() { command jq "$@" | tr -d '\r'; }   # Windows jq ends lines with CRLF

OUT=${OUT:-$DIR}
umask 077
mkdir -p "$OUT" || die "cannot create $OUT"
ALL=$( [[ -s "$DIR/raw/apps_all.jsonl" ]] && wc -l < "$DIR/raw/apps_all.jsonl" | tr -d ' ' || echo "")
DETECTED=$(date -r "$DIR/raw/model.jsonl" +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)

# ---------------------------------------------------------------- shared jq: the per-app model
read -r -d '' JQ_PRE <<'JQ'
def ts: # ISO 8601 date -> Unix seconds (UTC), in plain arithmetic: some Windows builds of
         # jq have no strptime, so the built-in ISO date parser fails there
  if . == null or . == "" then null
  else (capture("^(?<y>[0-9]{4})-(?<mo>[0-9]{2})-(?<d>[0-9]{2})([T ](?<h>[0-9]{2}):(?<mi>[0-9]{2})(:(?<s>[0-9]{2}))?)?") // null) as $c
  | if $c == null then null
    else ($c.mo | tonumber) as $m
    | (($c.y | tonumber) - (if $m <= 2 then 1 else 0 end)) as $y
    | (($y / 400) | floor) as $era | ($y - $era * 400) as $yoe
    | (((153 * (if $m > 2 then $m - 3 else $m + 9 end) + 2) / 5 | floor) + ($c.d | tonumber) - 1) as $doy
    | ($era * 146097 + $yoe * 365 + ($yoe / 4 | floor) - ($yoe / 100 | floor) + $doy - 719468) * 86400
      + (($c.h // "0") | tonumber) * 3600 + (($c.mi // "0") | tonumber) * 60 + (($c.s // "0") | tonumber)
    end
  end;
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def pct($n; $of): if $of == 0 then "0%" else "\(($n * 100 / $of) | round)%" end;
def top($n): group_by(.) | map({k: .[0], c: length}) | sort_by(-.c, .k) | .[:$n];
def table: if length == 0 then "| (none) | |" else map("| \(.k) | \(.c) |") | join("\n") end;
def rights: [.rbac[] | select(.rating >= 3) | "\(.role) @ \(.level)"] + [.entra[] | select(.rating >= 3) | .role]
            + [.api[] | select(.rating >= 3) | .perm] | unique | join("; ");

now as $now
| ($apps | map({key: .appId, value: (.secrets // [])}) | from_entries) as $secretsBy
| [ $model[]
    | . as $m
    | ([($secretsBy[$m.appId] // [])[] | {s: (.start | ts), e: (.end | ts), start, "end": .end}]) as $sec
    | . + {
        valid: [$sec[] | select(.e != null and .e >= $now)],
        noEnd: [$sec[] | select(.e == null)],
        crit: {
          azure: any(.rbac[]; .rating == 4),
          entra: any(.entra[]; .rating == 4),
          api:   any(.api[]; .rating == 4)
        }
      }
  ] as $A
JQ

# ---------------------------------------------------------------- worklist rows
read -r -d '' JQ_ROWS <<'JQ'
| def item($sev; $cat; $issue; $action; $details):
    {sev: $sev, cat: $cat, issue: $issue, action: $action, details: $details};
[ $A[] | . as $a
  | ($a.valid | map(.e) | min) as $nextE
  | ( (if $a.risk >= 3 and ($a.valid | length) > 0 then
        item($a.risk; "APP-PRIV-SECRET"; "Privileged app with a valid client secret";
          "Replace the client secret with workload identity federation or a managed identity. Until then: check the app's sign-in logs and secret history for misuse, rotate the secret, and remove rights it doesn't need.";
          "")
      else empty end),
      (if $a.risk >= 3 and ($a.valid | length) == 0 then
        item($a.risk - 1; "APP-PRIV-REVIEW"; "Privileged app without a valid client secret" + (if $a.certs > 0 then " (has certificates)" else "" end);
          "Review whether the app needs these rights and remove the rest. If it has a certificate, check where the private key is stored.";
          "")
      else empty end),
      (if ($a.owners | length) == 0 and $a.risk >= 2 then
        item($a.risk - 1; "APP-NO-OWNER"; "No owner or accountable team";
          "Find and record the accountable team (app notes, custom security attributes or CMDB). Don't add people as Entra owners of privileged apps: owners can add secrets.";
          "")
      else empty end),
      (if $a.risk >= 2 and any($a.valid[]; .s != null and .e - .s > 366 * 86400) then
        item(if $a.risk >= 3 then 2 else 1 end; "APP-LONG-SECRET"; "Client secret valid for more than a year";
          "Rotate to a short-lived secret (6-12 months at most) or migrate to federation. Enforce a maximum secret lifetime with an app management policy.";
          "")
      else empty end),
      (if $nextE != null and $nextE < $now + $days * 86400 then
        item(1; "APP-EXPIRING"; "Client secret expires within \($days) days";
          "Plan the rotation, or migrate to federation before it expires, to avoid an outage.";
          "Expires: \($a.valid | map(.end) | sort | first).")
      else empty end),
      (if $a.secrets > 0 and ($a.valid | length) == 0 and ($a.noEnd | length) == 0 then
        item(1; "APP-EXPIRED-ONLY"; "Only expired client secrets";
          "Delete the expired secrets. If the app is unused (check sign-in logs), disable its service principal and delete the app later.";
          "Expired secrets: \($a.expired).")
      else empty end),
      (if $a.spEnabled == false and ($a.valid | length) > 0 then
        item(1; "APP-DISABLED-SECRET"; "Service principal disabled but a client secret is still valid";
          "Remove the secret, and delete the app if it's no longer needed.";
          "Valid secrets: \($a.valid | length).")
      else empty end)
    )
  | . + {a: $a}
]
| map(.sev |= ([., 1] | max))
| sort_by(-.sev, .cat, (.a.name | ascii_downcase))
JQ

# rendering of the rows as CSV
read -r -d '' JQ_CSV <<'JQ'
| def csvrow: map(if . == null then "" else tostring end
                  | if test("^[=+\\-@\t\r]") then "'" + . else . end   # no formulas in Excel
                  | gsub("\""; "\"\"") | "\"" + . + "\"") | join($sep);
  (["item_id", "severity", "priority", "category", "issue", "action", "app_name", "app_id", "app_risk",
    "valid_secrets", "next_secret_expiry", "longest_secret_lifetime_days", "certificates", "sp_enabled",
    "owners", "privileged_rights", "details", "detected"] | csvrow),
  (.[] | .a as $a
       | ["\(.cat):\($a.appId)", (.sev | risklabel), (5 - .sev), .cat, .issue, .action, $a.name, $a.appId,
          ($a.risk | risklabel), ($a.valid | length), ($a.valid | map(.end) | sort | first // ""),
          ([$a.valid[] | select(.s != null) | (.e - .s) / 86400 | floor] | max // ""), $a.certs,
          (if $a.spEnabled == true then "yes" elif $a.spEnabled == false then "no" else "no service principal" end),
          ($a.owners | join(", ")), ($a | rights), .details, $detected]
       | csvrow)
JQ

# ---------------------------------------------------------------- report.md
read -r -d '' JQ_REPORT <<'JQ'
| ($A | length) as $n
| [$A[] | .valid[]] as $V
| "# App registrations with client secrets",
  "",
  "Inventory of \($detected) (appreg-inventory). Counts only.",
  "",
  "Apps in this inventory: **\($n)**" + (if $all != "" then " (of \($all) app registrations read)" else "" end) + ".",
  "",
  "## By risk",
  "",
  "| Risk | Apps | With a valid secret | Without an owner | Service principal disabled or missing |",
  "|---|---|---|---|---|",
  ( [4, 3, 2, 1][] as $r | [$A[] | select(.risk == $r)] as $g
    | "| \($r | risklabel) | \($g | length) | \([$g[] | select(.valid | length > 0)] | length) | \([$g[] | select(.owners | length == 0)] | length) | \([$g[] | select(.spEnabled != true)] | length) |" ),
  "",
  "## Client secrets",
  "",
  "- Apps with at least one valid secret: **\([$A[] | select(.valid | length > 0)] | length)** (\(pct([$A[] | select(.valid | length > 0)] | length; $n)))",
  "- Apps with only expired secrets: **\([$A[] | select(.secrets > 0 and (.valid | length) == 0 and (.noEnd | length) == 0)] | length)**",
  "- Valid secrets in total: **\($V | length)**",
  "- Valid secrets expiring within \($days) days: **\([$V[] | select(.e < $now + $days * 86400)] | length)**",
  "- Valid secrets with a lifetime over 1 year: **\([$V[] | select(.s != null and .e - .s > 366 * 86400)] | length)**, over 2 years: **\([$V[] | select(.s != null and .e - .s > 731 * 86400)] | length)**",
  "- Valid secrets created more than 1 year ago (never rotated since): **\([$V[] | select(.s != null and .s < $now - 365 * 86400)] | length)**",
  ( [$A[] | .noEnd[]] | length | if . > 0 then "- Secrets without an end date: **\(.)**" else empty end ),
  "- Apps that also have certificates: **\([$A[] | select(.certs > 0)] | length)**",
  "",
  "## Why apps are CRITICAL",
  "",
  "An app can match more than one reason.",
  "",
  "- Owner / Contributor / User Access Administrator / RBAC Administrator at root or management-group scope: **\([$A[] | select(.crit.azure)] | length)**",
  "- Tier-0 Entra ID role: **\([$A[] | select(.crit.entra)] | length)**",
  "- Takeover-capable API permission: **\([$A[] | select(.crit.api)] | length)**",
  "",
  "## Most common privileged access (HIGH and CRITICAL items)",
  "",
  "| Azure role @ level | Apps |", "|---|---|",
  ([$A[] | [.rbac[] | select(.rating >= 3) | "\(.role) @ \(.level)"] | unique[]] | top(10) | table),
  "",
  "| Entra ID role | Apps |", "|---|---|",
  ([$A[] | [.entra[] | select(.rating >= 3) | "\(.role) (\(.kind))"] | unique[]] | top(10) | table),
  "",
  "| API permission | Apps |", "|---|---|",
  ([$A[] | [.api[] | select(.rating >= 3) | "\(.perm) [\(.api)]"] | unique[]] | top(10) | table),
  "",
  "## Ownership and service principals",
  "",
  "- Apps without an owner: **\([$A[] | select(.owners | length == 0)] | length)** (\(pct([$A[] | select(.owners | length == 0)] | length; $n)))",
  "- Apps whose service principal is disabled: **\([$A[] | select(.spEnabled == false)] | length)**, of which with a valid secret: **\([$A[] | select(.spEnabled == false and (.valid | length > 0))] | length)**",
  "- Apps with no service principal in this tenant (not used here): **\([$A[] | select(.spEnabled == "no SP")] | length)**",
  "- Service principals with their own password credentials: **\([$A[] | select(.spOwnSecrets > 0)] | length)**",
  "",
  "## Cleanup candidates",
  "",
  "- LOW apps with only expired secrets: **\([$A[] | select(.risk == 1 and .secrets > 0 and (.valid | length) == 0)] | length)**",
  "- LOW apps without an owner: **\([$A[] | select(.risk == 1 and (.owners | length) == 0)] | length)**",
  "- Disabled or missing service principal: **\([$A[] | select(.spEnabled != true)] | length)**",
  "",
  "LOW means no Azure role, Entra role or application permission was found. Delegated permissions are not checked, so confirm an app is unused (sign-in logs) before deleting it.",
  "",
  "## Worklist",
  "",
  "| Severity | Items |", "|---|---|",
  ($items[0] | map(.sev) | group_by(.) | reverse
   | if length == 0 then "| (none) | |" else .[] | "| \(.[0] | risklabel) | \(length) |" end)
JQ

ARGS=(--slurpfile model "$DIR/raw/model.jsonl" --slurpfile apps "$DIR/raw/apps.jsonl"
      --argjson days "$DAYS" --arg all "$ALL" --arg detected "$DETECTED" --arg sep "$SEP")
# The rows go through a file: as a command-line argument they would hit the OS limit
# (128 KB per argument on Linux, 32 KB per command line on Windows).
ITEMS=$(mktemp) || die "cannot create a temporary file"
trap 'rm -f "$ITEMS"' EXIT
jq -n -c "${ARGS[@]}" "$JQ_PRE $JQ_ROWS" > "$ITEMS" || die "building the worklist failed"
{ printf '\xEF\xBB\xBF'; jq -r --arg sep "$SEP" --arg detected "$DETECTED" \
    'def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
    def rights: [.rbac[] | select(.rating >= 3) | "\(.role) @ \(.level)"] + [.entra[] | select(.rating >= 3) | .role]
                + [.api[] | select(.rating >= 3) | .perm] | unique | join("; "); . as $rows '"$JQ_CSV" < "$ITEMS"; } > "$OUT/appreg-worklist.csv" \
  || die "writing worklist.csv failed"
jq -n -r "${ARGS[@]}" --slurpfile items "$ITEMS" "$JQ_PRE $JQ_REPORT" > "$OUT/appreg-report.md" \
  || die "building report.md failed"

printf 'appreg-report.md     %s  (counts only - safe for the report)\n' "$OUT/appreg-report.md" >&2
printf 'appreg-worklist.csv  %s  (%s items, with names - internal)\n' "$OUT/appreg-worklist.csv" "$(jq -r 'length' < "$ITEMS")" >&2
