#!/usr/bin/env bash
# appreg-inventory.sh - READ-ONLY inventory of Entra ID app registrations that
# use client secrets, and of everything their service principals can do.
#
# For each app registration it collects:
#   * client secret / certificate counts, expiry and lifetime
#     (never the secret values or their "hint" characters)
#   * owners (they can add new secrets to the app)
#   * Azure RBAC role assignments on every scope (tenant root, management groups,
#     subscriptions, resource groups, resources) - direct and through groups
#   * Entra ID directory roles (active, and PIM-eligible if readable) - direct
#     and through groups
#   * API application permissions (Microsoft Graph, Exchange, ...)
# and gives each app a rough risk rating (a heuristic - verify by hand).
#
# Only read operations are used (az ad ... list, az rest --method GET,
# az graph query, az role ... list). Nothing in the tenant is changed.
#
# Needs: az CLI logged in (az login), the resource-graph extension
#        (az extension add --name resource-graph), jq 1.6+.
#        Reader (or more) on the tenant root management group, and
#        Global Reader / Directory Readers in Entra ID.
#
# Usage:
#   ./appreg-inventory.sh                 all app registrations with client secrets
#   ./appreg-inventory.sh -A              all app registrations
#   ./appreg-inventory.sh -a <appId> ...  only these apps (-a can be repeated)
#   ./appreg-inventory.sh -o <dir>        output folder
#                                         (default ./appreg-inventory-YYYYMMDD-HHMM)
#
# Output (tab-separated, opens in LibreOffice Calc / Excel):
#   summary.tsv          one row per app, highest risk first
#   azure_rbac.tsv       every Azure role assignment of every app
#   entra_roles.tsv      every Entra directory role of every app
#   api_permissions.tsv  every API application permission of every app
#   sp_own_secrets.tsv   (not with -a) service principals with their OWN password
#                        credentials - normal for SAML SSO apps, suspicious otherwise
#   raw/                 the raw JSON lines the reports are built from
# The output maps your tenant's privileged access: keep it private.

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Kotnyek József
# https://github.com/JoeHun0/appreg-inventory

set -uo pipefail

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

APP_IDS=()
INCLUDE_ALL=0
OUTDIR=""
while getopts ":a:Ao:h" opt; do
  case "$opt" in
    a) APP_IDS+=("$OPTARG") ;;
    A) INCLUDE_ALL=1 ;;
    o) OUTDIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 2 ;;
  esac
done

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

GUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
for id in "${APP_IDS[@]}"; do
  [[ "$id" =~ $GUID_RE ]] || die "not an application (client) ID: $id"
done

command -v az >/dev/null || die "az CLI not found"
command -v jq >/dev/null || die "jq not found (sudo apt install jq)"

# Windows (Git Bash, MSYS2, WSL calling the Windows az): Windows builds of az and jq
# end their output lines with CRLF, and MSYS rewrites arguments that start with "/"
# into Windows paths (--scope /providers/... becomes C:/Program Files/Git/providers/...).
# Both make Azure answer "Bad Request". Strip the CRs and turn the rewriting off for az.
az() { MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' command az "$@" | tr -d '\r'; }
jq() { command jq "$@" | tr -d '\r'; }
az extension show --name resource-graph --only-show-errors >/dev/null 2>&1 \
  || die "resource-graph extension missing: az extension add --name resource-graph"
TENANT_ID=$(az account show --query tenantId -o tsv --only-show-errors </dev/null 2>/dev/null) \
  && [[ -n "$TENANT_ID" ]] || die "not logged in: run az login"

umask 077
OUTDIR=${OUTDIR:-"./appreg-inventory-$(date +%Y%m%d-%H%M)"}
RAW="$OUTDIR/raw"
mkdir -p "$RAW" || die "cannot create $RAW"
for f in apps_all apps sps owners groups approles resources rbac roledefs dirdefs dirroles; do
  : > "$RAW/$f.jsonl"
done

GRAPH="https://graph.microsoft.com/v1.0"

# GET a Microsoft Graph collection, follow @odata.nextLink, print .value[] as JSON lines.
graph_all() {
  local url="$1" resp
  while [[ -n "$url" ]]; do
    resp=$(az rest --method GET --url "$url" -o json --only-show-errors </dev/null) || return 1
    jq -c '.value[]?' <<<"$resp" || return 1
    url=$(jq -r '."@odata.nextLink" // empty' <<<"$resp")
  done
}

# Azure Resource Graph query over the whole tenant (root management group),
# with paging; prints .data[] as JSON lines.
arg_all() {
  local q="$1" skip="" resp
  local args=(graph query -q "$q" --management-groups "$TENANT_ID" --first 1000 -o json --only-show-errors)
  while :; do
    if [[ -n "$skip" ]]; then
      resp=$(az "${args[@]}" --skip-token "$skip" </dev/null) || return 1
    else
      resp=$(az "${args[@]}" </dev/null) || return 1
    fi
    jq -c '.data[]?' <<<"$resp" || return 1
    skip=$(jq -r '.skip_token // empty' <<<"$resp")
    [[ -z "$skip" ]] && break
  done
}

# ---------------------------------------------------------------- 1. apps
# The JMESPath projection runs inside az: secret values and hints never leave it.
APP_QUERY='[].{objectId:id, appId:appId, name:displayName, created:createdDateTime, secrets:passwordCredentials[].{keyId:keyId, description:displayName, start:startDateTime, end:endDateTime}, certs:keyCredentials[].{keyId:keyId, end:endDateTime}}'
SP_QUERY='[].{id:id, appId:appId, name:displayName, type:servicePrincipalType, enabled:accountEnabled, sso:preferredSingleSignOnMode, ownSecrets:length(passwordCredentials || `[]`), ownCerts:length(keyCredentials || `[]`)}'

log "Tenant $TENANT_ID - reading app registrations..."
if ((${#APP_IDS[@]})); then
  for id in "${APP_IDS[@]}"; do
    az ad app list --filter "appId eq '$id'" --query "$APP_QUERY" -o json --only-show-errors </dev/null \
      | jq -c '.[]' >> "$RAW/apps_all.jsonl" || warn "app $id: lookup failed"
  done
else
  az ad app list --all --query "$APP_QUERY" -o json --only-show-errors </dev/null \
    | jq -c '.[]' > "$RAW/apps_all.jsonl" || die "could not list app registrations"
fi

if ((INCLUDE_ALL)) || ((${#APP_IDS[@]})); then
  cp "$RAW/apps_all.jsonl" "$RAW/apps.jsonl"
else
  jq -c 'select((.secrets // []) | length > 0)' "$RAW/apps_all.jsonl" > "$RAW/apps.jsonl"
fi
N=$(wc -l < "$RAW/apps.jsonl")
log "$(wc -l < "$RAW/apps_all.jsonl") app registrations read, $N selected."
((N > 0)) || { log "Nothing to do."; exit 0; }

# ---------------------------------------------------------------- 2. service principals
log "Reading service principals..."
if ((${#APP_IDS[@]})); then
  for id in "${APP_IDS[@]}"; do
    az ad sp list --filter "appId eq '$id'" --query "$SP_QUERY" -o json --only-show-errors </dev/null \
      | jq -c '.[]' >> "$RAW/sps.jsonl" || warn "service principal for $id: lookup failed"
  done
else
  az ad sp list --all --query "$SP_QUERY" -o json --only-show-errors </dev/null \
    | jq -c '.[]' > "$RAW/sps.jsonl" || die "could not list service principals"
fi

# ---------------------------------------------------------------- 3. per app: owners, groups, API permissions
i=0
while IFS=$'\t' read -r appId objId name; do
  i=$((i + 1))
  log "[$i/$N] $name"
  graph_all "$GRAPH/applications/$objId/owners?\$select=id,displayName,userPrincipalName" \
    | jq -c --arg a "$appId" '{appId: $a, owner: (.userPrincipalName // .displayName // .id)}' \
    >> "$RAW/owners.jsonl" || warn "$name: owners not readable"

  spId=$(jq -r --arg a "$appId" 'select(.appId == $a) | .id' "$RAW/sps.jsonl" | head -n1)
  if [[ -z "$spId" ]]; then
    warn "$name: no service principal in this tenant (app is not used here)"
    continue
  fi
  graph_all "$GRAPH/servicePrincipals/$spId/transitiveMemberOf?\$select=id,displayName" \
    | jq -c --arg s "$spId" 'select(."@odata.type" == "#microsoft.graph.group") | {spId: $s, groupId: .id, groupName: .displayName}' \
    >> "$RAW/groups.jsonl" || warn "$name: group memberships not readable"
  graph_all "$GRAPH/servicePrincipals/$spId/appRoleAssignments" \
    | jq -c --arg s "$spId" '{spId: $s, resourceId, appRoleId}' \
    >> "$RAW/approles.jsonl" || warn "$name: API permissions not readable"
done < <(jq -r '[.appId, .objectId, .name] | @tsv' "$RAW/apps.jsonl")

# principals whose roles we need: the apps' service principals + their groups
jq -r --slurpfile apps "$RAW/apps.jsonl" \
  '.appId as $a | select(any($apps[]; .appId == $a)) | .id' "$RAW/sps.jsonl" > "$RAW/principals.txt"
jq -r '.groupId' "$RAW/groups.jsonl" >> "$RAW/principals.txt"
sort -u -o "$RAW/principals.txt" "$RAW/principals.txt"

# ---------------------------------------------------------------- 4. API permission names
log "Resolving API permission names..."
jq -r '.resourceId' "$RAW/approles.jsonl" | sort -u | while read -r rid; do
  az rest --method GET --url "$GRAPH/servicePrincipals/$rid?\$select=id,displayName,appRoles" \
    -o json --only-show-errors </dev/null \
    | jq -c '{id, name: .displayName, roles: ((.appRoles // []) | map({key: .id, value: .value}) | from_entries)}' \
    >> "$RAW/resources.jsonl" || warn "API $rid: permission names not readable"
done

# ---------------------------------------------------------------- 5. Azure RBAC
log "Reading Azure role assignments (Resource Graph, whole tenant)..."
Q_RBAC="authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalType = tostring(properties.principalType)
| where principalType in~ ('ServicePrincipal', 'Group')
| project id, principalId = tostring(properties.principalId), principalType,
          roleDefinitionId = tostring(properties.roleDefinitionId), scope = tostring(properties.scope)"
arg_all "$Q_RBAC" >> "$RAW/rbac.jsonl" || warn "Resource Graph role assignment query failed - RBAC may be incomplete"

# Management-group and root scopes are read directly as well, to be sure they are covered.
log "Reading role assignments on management groups and the root scope..."
RA_QUERY='[].{id:id, principalId:principalId, principalType:principalType, roleDefinitionId:roleDefinitionId, scope:scope}'
ra_list() {
  az role assignment list --scope "$1" --fill-principal-name false --fill-role-definition-name false \
    --query "$RA_QUERY" -o json --only-show-errors </dev/null 2>/dev/null \
  || az role assignment list --scope "$1" --query "$RA_QUERY" -o json --only-show-errors </dev/null
}
mapfile -t MGS < <(az account management-group list --query '[].name' -o tsv --only-show-errors </dev/null) \
  || warn "could not list management groups"
for mg in "${MGS[@]}"; do
  ra_list "/providers/Microsoft.Management/managementGroups/$mg" | jq -c '.[]' >> "$RAW/rbac.jsonl" \
    || warn "management group $mg: role assignments not readable"
done
ra_list "/" 2>/dev/null | jq -c '.[] | select(.scope == "/")' >> "$RAW/rbac.jsonl" 2>/dev/null \
  || warn "root scope (/) role assignments not readable (needs elevated access) - skipped"

log "Reading Azure role definitions..."
Q_ROLEDEFS="authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| project id, name = tolower(name), roleName = tostring(properties.roleName)"
arg_all "$Q_ROLEDEFS" >> "$RAW/roledefs.jsonl" || warn "Resource Graph role definition query failed"
az role definition list --query '[].{name:name, roleName:roleName}' -o json --only-show-errors </dev/null \
  | jq -c '.[]' >> "$RAW/roledefs.jsonl" || warn "az role definition list failed - some role names may show as GUIDs"

# ---------------------------------------------------------------- 6. Entra directory roles
log "Reading Entra directory roles..."
graph_all "$GRAPH/roleManagement/directory/roleDefinitions?\$select=id,displayName,templateId" \
  > "$RAW/dirdefs.jsonl" || warn "directory role definitions not readable - role names may show as IDs"

# active assignments: whole tenant in one go, or per principal if that is refused
if ! graph_all "$GRAPH/roleManagement/directory/roleAssignments" \
     | jq -c '{kind: "active", id, principalId, roleDefinitionId, directoryScopeId}' >> "$RAW/dirroles.jsonl"; then
  warn "tenant-wide role assignment list refused, querying per principal"
  while read -r p; do
    graph_all "$GRAPH/roleManagement/directory/roleAssignments?\$filter=principalId%20eq%20'$p'" \
      | jq -c '{kind: "active", id, principalId, roleDefinitionId, directoryScopeId}' >> "$RAW/dirroles.jsonl" \
      || warn "principal $p: directory roles not readable"
  done < "$RAW/principals.txt"
fi

# PIM-eligible assignments (needs PIM licensing and read consent; skipped if refused)
if ! graph_all "$GRAPH/roleManagement/directory/roleEligibilitySchedules" \
     | jq -c '{kind: "eligible", id, principalId, roleDefinitionId, directoryScopeId}' >> "$RAW/dirroles.jsonl"; then
  first=1
  while read -r p; do
    if ! graph_all "$GRAPH/roleManagement/directory/roleEligibilitySchedules?\$filter=principalId%20eq%20'$p'" \
         | jq -c '{kind: "eligible", id, principalId, roleDefinitionId, directoryScopeId}' >> "$RAW/dirroles.jsonl"; then
      if ((first)); then
        warn "PIM-eligible role assignments not readable - only active roles are reported"
        break
      fi
    fi
    first=0
  done < "$RAW/principals.txt"
fi

# ---------------------------------------------------------------- 7. build the model
log "Building reports..."
read -r -d '' JQ_MODEL <<'JQ'
def lc: ascii_downcase;
def ts: if . == null then null
        else (sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | try fromdateiso8601 catch null) end;
def level: if . == "/" then "root"
           elif test("^/subscriptions/[^/]+$"; "i") then "subscription"
           elif test("^/subscriptions/[^/]+/resourcegroups/[^/]+$"; "i") then "resourceGroup"
           elif test("^/providers/microsoft.management/managementgroups/[^/]+$"; "i") then "managementGroup"
           else "resource" end;
def guid: (lc | capture("roledefinitions/(?<g>[^/]+)$").g) // lc;

def priv_azure: ["Owner", "User Access Administrator", "Role Based Access Control Administrator", "Contributor"];
def crit_entra: ["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
                 "Application Administrator", "Cloud Application Administrator", "Hybrid Identity Administrator",
                 "Partner Tier2 Support", "Domain Name Administrator", "External Identity Provider Administrator",
                 "Conditional Access Administrator", "Security Administrator", "Authentication Policy Administrator",
                 "Intune Administrator"];
def crit_api: ["RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
               "Directory.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
               "Policy.ReadWrite.AuthenticationMethod", "Domain.ReadWrite.All", "PrivilegedAccess.ReadWrite.AzureADGroup",
               "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup", "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
               "RoleAssignmentSchedule.ReadWrite.Directory", "RoleEligibilitySchedule.ReadWrite.Directory",
               "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementRBAC.ReadWrite.All", "full_access_as_app"];

def rate_azure: if (.role | IN(priv_azure[])) and (.level == "root" or .level == "managementGroup") then 4
                elif (.role | IN(priv_azure[])) and .level == "subscription" then 3
                else 2 end;
def rate_entra: if (.role | IN(crit_entra[])) then 4 else 3 end;
def rate_api: if .perm == "(default access)" then 1
              elif (.perm | IN(crit_api[])) then 4
              elif (.perm | test("ReadWrite|FullControl|full_access|^Mail\\.(Read|Send)")) then 3
              else 2 end;

($sps      | map({key: .appId, value: .}) | from_entries) as $spByApp
| ($groups | group_by(.spId) | map({key: .[0].spId, value: .}) | from_entries) as $grpBySp
| ($owners | group_by(.appId) | map({key: .[0].appId, value: map(.owner)}) | from_entries) as $ownByApp
| ($rbac   | unique_by(.id | lc) | group_by(.principalId | lc) | map({key: (.[0].principalId | lc), value: .}) | from_entries) as $rbacBy
| ($roledefs | map({key: (.name | lc), value: .roleName}) | from_entries) as $rd
| ([$dirdefs[] | {key: .id, value: .displayName}] + [$dirdefs[] | select(.templateId) | {key: .templateId, value: .displayName}] | from_entries) as $dd
| ($dirroles | unique_by([.kind, .id]) | group_by(.principalId) | map({key: .[0].principalId, value: .}) | from_entries) as $dirBy
| ($approles | group_by(.spId) | map({key: .[0].spId, value: .}) | from_entries) as $apBySp
| ($resources | map({key: .id, value: .}) | from_entries) as $res
| $apps[]
| . as $app
| $spByApp[$app.appId] as $sp
| (if $sp then [{id: $sp.id, via: "direct"}] + [($grpBySp[$sp.id] // [])[] | {id: .groupId, via: ("group: " + .groupName)}] else [] end) as $principals
| (now) as $now
| {
    name, appId, objectId,
    spId: ($sp.id // ""),
    spEnabled: (if $sp then $sp.enabled else "no SP" end),
    secrets: ((.secrets // []) | length),
    expired: ([(.secrets // [])[] | (.end | ts) | select(. != null and . < $now)] | length),
    nextExpiry: ([(.secrets // [])[] | select((.end | ts) as $e | $e != null and $e >= $now) | .end] | sort | first // ""),
    maxLifetimeDays: ([(.secrets // [])[] | {s: (.start | ts), e: (.end | ts)} | select(.s and .e) | ((.e - .s) / 86400 | floor)] | max // ""),
    certs: ((.certs // []) | length),
    spOwnSecrets: ($sp.ownSecrets // 0),
    owners: ($ownByApp[$app.appId] // []),
    rbac: [$principals[] as $p | ($rbacBy[$p.id | lc] // [])[]
           | {via: $p.via, role: ($rd[.roleDefinitionId | guid] // (.roleDefinitionId | guid)), level: (.scope | level), scope}
           | . + {rating: rate_azure}],
    entra: [$principals[] as $p | ($dirBy[$p.id] // [])[]
            | {via: $p.via, role: ($dd[.roleDefinitionId] // .roleDefinitionId), kind, scope: .directoryScopeId}
            | . + {rating: rate_entra}],
    api: [(if $sp then ($apBySp[$sp.id] // []) else [] end)[]
          | {api: ($res[.resourceId].name // .resourceId),
             perm: (if .appRoleId == "00000000-0000-0000-0000-000000000000" then "(default access)"
                    else ($res[.resourceId].roles[.appRoleId] // .appRoleId) end)}
          | . + {rating: rate_api}]
  }
| . + {risk: ([.rbac[].rating, .entra[].rating, .api[].rating, 1] | max)}
JQ

jq -n -c \
  --slurpfile apps "$RAW/apps.jsonl" --slurpfile sps "$RAW/sps.jsonl" \
  --slurpfile groups "$RAW/groups.jsonl" --slurpfile owners "$RAW/owners.jsonl" \
  --slurpfile rbac "$RAW/rbac.jsonl" --slurpfile roledefs "$RAW/roledefs.jsonl" \
  --slurpfile dirdefs "$RAW/dirdefs.jsonl" --slurpfile dirroles "$RAW/dirroles.jsonl" \
  --slurpfile approles "$RAW/approles.jsonl" --slurpfile resources "$RAW/resources.jsonl" \
  "$JQ_MODEL" > "$RAW/model.jsonl" || die "report building failed (raw data kept in $RAW)"

# ---------------------------------------------------------------- 8. reports
JQ_LABEL='def risklabel: ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][.];'

jq -r -s "$JQ_LABEL"'
  (["risk", "app", "appId", "clientSecrets", "expiredSecrets", "nextSecretExpiry", "maxSecretLifetimeDays",
    "certificates", "spOwnSecrets", "spEnabled", "owners", "azurePrivilegedRoles", "azureAssignments",
    "entraRoles", "riskyApiPermissions"] | @tsv),
  (sort_by(-.risk, (.name | ascii_downcase))[]
   | [(.risk | risklabel), .name, .appId, .secrets, .expired, .nextExpiry, .maxLifetimeDays, .certs, .spOwnSecrets,
      .spEnabled, (.owners | join(", ")),
      ([.rbac[] | select(.rating >= 3) | "\(.role)@\(.level)"] | group_by(.) | map("\(.[0]) x\(length)") | join("; ")),
      (.rbac | length),
      ([.entra[] | "\(.role) (\(.kind))"] | unique | join("; ")),
      ([.api[] | select(.rating >= 3) | "\(.perm) [\(.api)]"] | unique | join("; "))]
   | @tsv)' "$RAW/model.jsonl" > "$OUTDIR/summary.tsv"

jq -r -s "$JQ_LABEL"'
  (["rating", "app", "appId", "via", "role", "level", "scope"] | @tsv),
  ([.[] | . as $a | .rbac[] | . + {app: $a.name, appId: $a.appId}]
   | sort_by(-.rating, (.app | ascii_downcase), .scope)[]
   | [(.rating | risklabel), .app, .appId, .via, .role, .level, .scope] | @tsv)' "$RAW/model.jsonl" > "$OUTDIR/azure_rbac.tsv"

jq -r -s "$JQ_LABEL"'
  (["rating", "app", "appId", "via", "role", "assignment", "directoryScope"] | @tsv),
  ([.[] | . as $a | .entra[] | . + {app: $a.name, appId: $a.appId}]
   | sort_by(-.rating, (.app | ascii_downcase))[]
   | [(.rating | risklabel), .app, .appId, .via, .role, .kind, .scope] | @tsv)' "$RAW/model.jsonl" > "$OUTDIR/entra_roles.tsv"

jq -r -s "$JQ_LABEL"'
  (["rating", "app", "appId", "api", "permission"] | @tsv),
  ([.[] | . as $a | .api[] | . + {app: $a.name, appId: $a.appId}]
   | sort_by(-.rating, (.app | ascii_downcase), .perm)[]
   | [(.rating | risklabel), .app, .appId, .api, .perm] | @tsv)' "$RAW/model.jsonl" > "$OUTDIR/api_permissions.tsv"

if ((${#APP_IDS[@]} == 0)); then
  jq -r -s '
    (["servicePrincipal", "appId", "type", "singleSignOnMode", "ownPasswordCredentials", "ownKeyCredentials"] | @tsv),
    (map(select(.ownSecrets > 0)) | sort_by(.name | ascii_downcase)[]
     | [.name, .appId, .type, (.sso // ""), .ownSecrets, .ownCerts] | @tsv)' "$RAW/sps.jsonl" > "$OUTDIR/sp_own_secrets.tsv"
fi

log "Done. Apps by risk:"
jq -r -s "$JQ_LABEL"'group_by(.risk) | reverse[] | "  \(.[0].risk | risklabel): \(length)"' "$RAW/model.jsonl" >&2
log "Reports in $OUTDIR (keep them private)."
