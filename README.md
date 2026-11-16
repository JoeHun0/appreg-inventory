# appreg-inventory

A read-only Bash script that lists the **Entra ID app registrations that use client secrets** and shows
**everything each of them can do**: Azure RBAC on every scope, Entra ID directory roles and API
permissions, including what they get through group membership. It sorts the apps by a rough risk rating.

```bash
./appreg-inventory.sh            # every app registration that has a client secret
```

## Why

A client secret is a long-lived password for an application. Anyone who has it can sign in as the app
from anywhere on the internet. Secrets often end up in CI/CD systems (Azure DevOps service connections,
GitHub secrets, pipeline variables), scripts and config files. The service principals behind them often
hold wide roles such as *Contributor* or *Owner* on whole subscriptions or management groups.

Most of these secrets don't need to exist. Pipelines can use **workload identity federation (OIDC)**,
and Azure-hosted workloads can use **managed identities**. Neither has a secret to steal. Before you can
remove the secrets, you need to know which apps have them and how much damage each one could do. That
information is spread across the Azure portal (one subscription at a time), Entra ID roles, API
permissions and group memberships. This script puts it in one place.

## What it collects

For each selected app registration:

| | |
|---|---|
| **Credentials** | number of client secrets and certificates, how many are expired, next expiry, longest secret lifetime |
| **Owners** | users and service principals that own the app (they can add new secrets to it) |
| **Azure RBAC** | role assignments on the tenant root (`/`), management groups, subscriptions, resource groups and resources |
| **Entra ID roles** | active directory role assignments, plus PIM-eligible ones if your account can read them |
| **API permissions** | application permissions granted to the app (Microsoft Graph, Exchange, …) by name |
| **Groups** | Azure roles and Entra roles the app gets through (nested) group membership |

Across the whole tenant, it also lists service principals that have their **own** password credentials.
These don't show on the app registration, so they're easy to miss (see [Output](#output)).

## Safety

- **Read-only.** The script only lists and reads: `az ad … list`, `az rest --method GET`, `az graph query`,
  `az role … list`. It changes nothing in Azure or Entra ID.
- **No secret material.** Graph returns a `hint` (the first characters) with every client secret. The
  script uses an `az --query` projection to drop it inside `az`, so hints and secret values never reach
  the screen or disk. The test suite checks this.
- **The output is sensitive.** It maps every privileged non-human identity in your tenant, which is
  exactly what an attacker would want. Files are created mode `600` (owner-only). Keep them private, and
  never commit them (the `.gitignore` in this repo excludes them).

## Requirements

- **Bash 4+** and **jq 1.6+**. Works on Linux, WSL, and macOS with Homebrew `bash`.
  [Azure Cloud Shell](https://shell.azure.com) has both.
- **Azure CLI**, signed in with `az login`, plus the Resource Graph extension:
  ```bash
  az extension add --name resource-graph
  ```
- **Permissions** for a complete picture:
  - Azure: **Reader** on the tenant root management group (or on every management group and
    subscription you want covered).
  - Entra ID: **Global Reader**, or Directory Readers (Global Reader is needed for directory role
    assignments and PIM eligibility).
  - Root-scope (`/`) assignments are visible only with
    [elevated access](https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin).
    Without it they're skipped with a warning.

## Usage

```bash
git clone https://github.com/JoeHun0/appreg-inventory.git
cd appreg-inventory
./appreg-inventory.sh                         # apps with client secrets (default)
./appreg-inventory.sh -A                      # all app registrations
./appreg-inventory.sh -a <appId> -a <appId>   # only these applications (client IDs)
./appreg-inventory.sh -o ~/reports/2026-11    # choose the output folder
./appreg-inventory.sh -h                      # help
```

Progress goes to stderr. The script makes about three Microsoft Graph calls per app, so a few hundred
apps take roughly 10–20 minutes. Run it from a folder outside any git repository.

## Output

Results go to `./appreg-inventory-YYYYMMDD-HHMM/` (or the folder given with `-o`) as tab-separated files.
They open directly in LibreOffice Calc or Excel.

| File | Contents |
|---|---|
| `summary.tsv` | One row per app, highest risk first: secrets, expired secrets, next expiry, longest secret lifetime (days), certificates, SP's own secrets, SP enabled, owners, privileged Azure roles per scope level (e.g. `Owner@managementGroup x1; Contributor@subscription x40`), number of Azure assignments, Entra roles, risky API permissions |
| `azure_rbac.tsv` | Every Azure role assignment: rating, app, `via` (`direct` or `group: <name>`), role, scope level, scope |
| `entra_roles.tsv` | Every Entra ID directory role: rating, app, `via`, role, `active`/`eligible`, directory scope |
| `api_permissions.tsv` | Every API application permission: rating, app, API, permission |
| `sp_own_secrets.tsv` | Service principals with their own password credentials (not written with `-a`). This is **normal for SAML SSO apps** (`singleSignOnMode = saml`) and **worth investigating for anything else**: credentials added directly to a service principal are a known persistence technique. |
| `raw/` | The JSON lines the reports are built from, for your own queries with `jq` |

## Risk rating

The rating is a **heuristic to sort by**, not a verdict. Each role or permission gets a rating, and the app
gets the highest one.

| Rating | Azure RBAC | Entra ID roles | API permissions |
|---|---|---|---|
| **CRITICAL** | Owner, User Access Administrator, Role Based Access Control Administrator or Contributor at **root or management group** level | Roles that lead to tenant takeover or auth bypass: Global Admin, Privileged Role Admin, Privileged Authentication Admin, Application Admin, Cloud Application Admin, Hybrid Identity Admin, Conditional Access Admin, Security Admin, Intune Admin, … | `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Domain.ReadWrite.All`, `full_access_as_app`, … |
| **HIGH** | The same roles at **subscription** level | Any other directory role | Other write or full-control permissions (`*ReadWrite*`, `*FullControl*`), `Mail.Read`/`Mail.Send` |
| **MEDIUM** | Any role on a resource group or resource, or a non-privileged role higher up | – | Read permissions (e.g. `User.Read.All`) |
| **LOW** | No roles | – | Default access only |

The full lists are at the top of the `JQ_MODEL` block in the script. Adjust them to your own threat model.

## How it works

1. App registrations: `az ad app list` (with a `--query` projection that drops secret hints).
2. Service principals: `az ad sp list`.
3. For each app: owners, transitive group memberships and app role assignments (Microsoft Graph via `az rest`).
4. Azure role assignments across the whole tenant in one paged
   [Azure Resource Graph](https://learn.microsoft.com/azure/governance/resource-graph/) query
   (`authorizationresources`). Management-group and root-scope assignments are also read with
   `az role assignment list`, and duplicates are removed.
5. Role names from Resource Graph and `az role definition list`.
6. Entra ID directory role assignments (tenant-wide, or per principal if that is refused) and PIM
   eligibility schedules (skipped with a warning if not readable).
7. Everything is joined in `jq`: the app's service principal plus its groups give its principals, then
   each principal's roles and permissions are looked up.

## Limitations

- **Azure public cloud only.** The Microsoft Graph endpoint is hard-coded (`graph.microsoft.com`).
- **Not covered:** classic subscription administrators, Azure DevOps or GitHub-side configuration
  (which pipelines use which app), and data-plane permissions (Key Vault access policies, storage SAS,
  SQL users, Exchange RBAC for applications).
- **Delegated permissions** (OAuth2 grants acting on behalf of users) aren't listed. Only application
  permissions are.
- **Timing:** Resource Graph can lag a few minutes behind very recent role changes.
- **Managed identities** aren't included because they can't have client secrets. Use `-A`, or adapt the
  script, if you need them.

## After the inventory

These are common next steps, roughly in order:

1. Treat secrets with critical or high reach as possibly exposed: rotate them, or remove them once
   step 2 is done.
2. Replace secrets with
   [workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)
   (Azure DevOps, GitHub Actions, Kubernetes) or managed identities.
3. Cut Azure roles down to the scopes each app really deploys to. Avoid Owner and User Access
   Administrator, or limit them with role assignment conditions.
4. Block new password credentials with a tenant-wide
   [app management policy](https://learn.microsoft.com/graph/api/resources/tenantappmanagementpolicy)
   (check the licensing requirements first).
5. Alert on credentials added to applications and service principals (Entra ID audit log), and on
   service principal sign-ins from unexpected locations.

## Tests

```bash
tests/run-tests.sh
```

The tests run the script against a mock `az` (`tests/mock/az`) that simulates a small tenant, including
paging, duplicate assignments, roles through groups and refused API calls. They need only `bash` and `jq`,
not Azure access. They also run on every push through GitHub Actions.

## License

[MIT](LICENSE)
