#!/usr/bin/env bash
# appreg-summary.sh - turns an appreg-inventory output folder into a short summary
# in Markdown: counts by risk, secret validity and lifetime, ownership, why apps are
# CRITICAL, the most common privileged roles and permissions, and cleanup candidates.
#
# Usage:
#   ./appreg-summary.sh <output folder>        counts only - safe to paste into a report
#   ./appreg-summary.sh -n <output folder>     also list the CRITICAL and HIGH apps and
#                                              the secrets that expire soon (internal use)
#   ./appreg-summary.sh -d 60 <output folder>  "expires soon" window in days (default 30)
#
# Reads raw/model.jsonl and raw/apps.jsonl from the folder. Needs only jq; no Azure access.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/appreg-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

NAMES=0
DAYS=30
while getopts ":nd:h" opt; do
  case "$opt" in
    n) NAMES=1 ;;
    d) DAYS="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
(($# == 1)) || die "give one appreg-inventory output folder (-h for help)"
[[ "$DAYS" =~ ^[0-9]+$ ]] || die "-d needs a number of days"
DIR="$1"
for f in model apps; do
  [[ -s "$DIR/raw/$f.jsonl" ]] || die "$DIR/raw/$f.jsonl not found - is this an appreg-inventory output folder?"
done
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"
jq() { command jq "$@" | tr -d '\r'; }   # Windows jq ends lines with CRLF

ALL=$( [[ -s "$DIR/raw/apps_all.jsonl" ]] && wc -l < "$DIR/raw/apps_all.jsonl" | tr -d ' ' || echo "")

jq -n -r --slurpfile model "$DIR/raw/model.jsonl" --slurpfile apps "$DIR/raw/apps.jsonl" \
  --argjson days "$DAYS" --argjson names "$NAMES" --arg all "$ALL" --arg dir "$DIR" '
def ts: if . == null then null
        else (sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | try fromdateiso8601 catch null) end;
def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];
def pct($n; $of): if $of == 0 then "0%" else "\(($n * 100 / $of) | round)%" end;
def top($n): group_by(.) | map({k: .[0], c: length}) | sort_by(-.c, .k) | .[:$n];
def table: if length == 0 then "| (none) | |" else map("| \(.k) | \(.c) |") | join("\n") end;

now as $now
| ($apps | map({key: .appId, value: (.secrets // [])}) | from_entries) as $secretsBy
| [ $model[]
    | . as $m
    | ([($secretsBy[$m.appId] // [])[] | {s: (.start | ts), e: (.end | ts), start, end}]) as $sec
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
| ($A | length) as $n
| [$A[] | .valid[]] as $V
| (
  "# appreg-inventory summary",
  "",
  "Source: `\($dir)`. Generated \(now | strftime("%Y-%m-%d %H:%M")) UTC.",
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
  "- Apps with only expired secrets (delete the secrets, or the app if unused): **\([$A[] | select(.secrets > 0 and (.valid | length) == 0 and (.noEnd | length) == 0)] | length)**",
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
  ([$A[] | [.entra[] | "\(.role) (\(.kind))"] | unique[]] | top(10) | table),
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
  ( if $names == 1 then
      "",
      "## CRITICAL and HIGH apps (internal - contains names)",
      "",
      "| Risk | App | App ID | Valid secrets | Owners | Reasons |",
      "|---|---|---|---|---|---|",
      ( $A | map(select(.risk >= 3)) | sort_by(-.risk, (.name | ascii_downcase))[]
        | "| \(.risk | risklabel) | \(.name) | \(.appId) | \(.valid | length) | \(if (.owners | length) == 0 then "none" else (.owners | join(", ")) end) | \(
            ([.rbac[] | select(.rating >= 3) | "\(.role) @ \(.level)"] + [.entra[] | select(.rating >= 3) | .role]
             + [.api[] | select(.rating >= 3) | .perm] | unique | join("; "))) |" ),
      "",
      "## Secrets expiring within \($days) days (internal - contains names)",
      "",
      "| Expires | App | Risk |", "|---|---|---|",
      ( [$A[] | . as $a | .valid[] | select(.e < $now + $days * 86400) | {end, name: $a.name, risk: $a.risk}]
        | if length == 0 then "| (none) | | |" else sort_by(.end)[] | "| \(.end) | \(.name) | \(.risk | risklabel) |" end )
    else empty end )
)'
