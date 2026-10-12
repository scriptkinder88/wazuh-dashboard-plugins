# CIS-CAT bridge release packages

The sources of the three release packages. The built packages are release attachments, never
committed (`out/` is ignored).

| Folder | Package | Runs on |
|--------|---------|---------|
| [`master/`](master/README.txt) | `ciscat-master-<v>.zip` | the Wazuh master (and the dashboard when on the same host) |
| [`agent-windows/`](agent-windows/README.txt) | `ciscat-agent-windows-<v>[-assessor-<a>].zip` | every Windows agent |
| [`agent-linux/`](agent-linux/README.txt) | `ciscat-agent-linux-<v>[-assessor-<a>].tar.gz` | every Linux / Unix-like agent |
| [`ansible/`](ansible/) | playbook and role `ciscat_agent` | the Ansible controller, to roll out the agent packages |

## Build

```sh
python3 build.py --plugin <dashboard plugin zip name> --plugin-sha256 <sha256> [--out DIR]
```

The agent installers embed the launcher and bootstrap scripts of this tree, with their SHA-256.
With `--assessor-windows <folder> --assessor-linux <folder> --assessor-version X.Y.Z` the agent
packages also carry CIS-CAT Pro Assessor (its `license`, `reports` and `logs` folders are left
out). Those packages contain licensed CIS software: keep them in the internal release store.

Release attachments: the three packages, `SHA256SUMS`, and the dashboard plugin zip of the same
commit.

## Install order

1. Master: `ciscat-master-setup.sh` (see `master/README.txt`). It creates the manifest signing
   key and writes the public keys the agents need to `master/agent-keys/`.
2. Agents: the agent installer with the master's public key next to it, by hand or with
   `ansible-playbook -i inventory.ini ansible/ciscat-agents.yml -e ciscat_release_dir=<dir>`
   (`<dir>` holds the agent packages and `agent-keys/`).
3. End-to-end test: `ciscat-e2e-master.py pre|run|post` on the master, the e2e script of each
   agent package on the agents.

Packages are unpacked in a root/Administrators-only folder: `/opt/ciscat/install/<v>`,
`C:\CIS\install\<v>`. The installers refuse (Linux) or warn about (Windows) a home, temporary or
user-writable folder.

## Updates

| What changes | How it reaches the agents | What to do |
|--------------|---------------------------|------------|
| Assessment and conversion scripts, benchmarks, OVAL/CPE, settings | from the master at every run, through the signed manifest | update the master |
| CIS-CAT Pro license | from the master at every run, when `/opt/ciscat/license/license.xml` exists | replace that file, then `ciscat-fleet.py apply` |
| CIS-CAT Pro Assessor (new version or fix) | full agent package (`ASSESSOR_VERSION`): installed when the version differs, license kept, rolled back when it does not start | roll out the new agent package |
| Launcher and bootstrap | agent package | roll out the agent package |

The agent installers are idempotent: running them again with the same package changes nothing
but the files that differ.
