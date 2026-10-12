# Terraform: CIS-CAT bridge, dashboard plugin and baseline groups

The module `modules/wazuh-ciscat` installs and configures the CIS-CAT bridge on **existing** Wazuh
hosts (4.14.x), over SSH. It does not create machines and needs no provider: the caller reads the
secrets (for example from Vault, as in `examples/site`) and passes them in. Wazuh 5.0 is not
supported yet: `wazuh_major = 5` is refused, since the bridge installer has no indexer options.

## What Terraform manages, and what it leaves to the dashboard

| Managed by Terraform                                                                      | Left to the dashboard                        |
| ----------------------------------------------------------------------------------------- | -------------------------------------------- |
| Bridge version (the installer and its SHA-256)                                            | FIM rules of every other group               |
| Dashboard plugin version (zip and SHA-256)                                                | CIS-CAT exclusions, target groups, schedules |
| API credentials (root-only files)                                                         | Groups created from the agent list           |
| Licensed benchmarks in `/opt/ciscat/benchmarks`                                           | Agents added to groups by hand               |
| Groups starting with `baseline-`: their whole `agent.conf` and the agents listed for them |                                              |
| First CIS-CAT exclusions (CSV seed, imported only by the first install)                   |                                              |

Each object has a single owner, so a `terraform apply` never undoes work done in the dashboard, and
the dashboard never fights Terraform. In the FIM tab the form warns when a rule targets a group
managed by Terraform: such a change would be overwritten at the next apply.

## How it works

- Files go to `~/.ciscat-terraform` of the SSH user (mode 700), are checked (SHA-256) and moved in
  place as root. A user other than root needs passwordless `sudo`.
- **Secrets** are written by the file provisioner, so they never appear on a command line, in
  `ps` or in the Terraform output: the API password to `/opt/ciscat/etc/.ciscat_api_pass` (600).
  `ciscat-orchestrator.conf` only has `api_user` and `api_pass_file` set, other settings stay. The
  state keeps hashes of the secrets (to know when to rewrite them): keep it encrypted and
  access-controlled, as any Terraform state.
- **Installer:** the bridge installer runs on the master (and on the dashboard host when it is
  separate, for the plugin). It is idempotent and keeps a backup (`--rollback`). A new version is
  a change of `installer` (path and SHA-256); the plugin likewise.
- **Baseline groups:** `ciscat-fleet.py baseline` creates the groups, writes their `agent.conf`
  when it differs (the manager validates it: a refused file fails the apply) and adds the listed
  agents. Rules carry the dashboard's audit comment (reason, ticket, owner, `by: terraform`), so the
  FIM tab shows them with their reason. By default a group is rewritten only when the baseline
  changes; `baseline_reconcile = true` rewrites it at every apply, putting back changes made
  elsewhere.
- **Destroy** removes nothing from the hosts: uninstall with the installer's `--rollback`, and
  delete baseline groups from the dashboard once they are no longer in the code.

## Use

```hcl
module "wazuh_ciscat" {
  source = "./modules/wazuh-ciscat"

  wazuh_major  = 4
  master       = { host = "<master address>", user = "root" }
  installer    = { path = "ciscat-bridge-install-2.3.0.sh", sha256 = "<from the .sha256 file>" }
  plugin       = { path = "<plugin zip from the build>", sha256 = "<sha256sum of the zip>" }
  api_password = data.vault_kv_secret_v2.wazuh.data["api_password"]

  baseline_groups = yamldecode(file("baseline.yaml")).groups
}
```

`examples/site` reads the secrets from Vault (KV v2: `api_user`, `api_password`) and the baseline
from `baseline.yaml`. Copy `terraform.tfvars.example` to `terraform.tfvars`: it holds addresses and
paths, never secrets.

## Baseline groups

```yaml
groups:
  baseline-linux:
    os: Linux # Linux, Windows, or omit for any
    agents: [web-01] # optional: existing agents to add (enrollment groups are better)
    options: { frequency: '43200' }
    fim:
      - kind: directories # directories, ignore, nodiff, windows_registry, registry_ignore
        path: /etc/ssh
        attrs: { whodata: 'yes' }
        reason: who changes access configuration
        ticket: CHG-1234
        owner: SOC
```

The same rules as in the dashboard apply: wildcards work in `directories` and `windows_registry`,
while `ignore` and `nodiff` compare the path literally or as an sregex (`type: sregex`, with only
`^`, `$` and `|`). Paths and attributes cannot contain `< > & "`; every rule needs a reason.

## Requirements

- Terraform 1.9 or later (validations that refer to other variables).
- SSH access to the master (and to the dashboard host when separate), `python3` and `sha256sum`
  on them.
- The bridge installer from `installer/build.py` and the plugin zip from the dashboard build. The
  CIS benchmarks are licensed and not part of this repository: point `benchmarks_dir` to the site's
  copy.
