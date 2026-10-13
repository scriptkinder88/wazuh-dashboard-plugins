# CIS-CAT bridge: operations guide

Day-to-day running of the bridge on Wazuh 4.14.7: installation, updates, routine checks and the
usual problems. For what the bridge is, see `overview.md`; for the design, the main `README.md`.

All commands run as root on the Wazuh master unless the section says otherwise.

## 1. Where things are

**Master**

| Path                                         | What                                                                 |
| -------------------------------------------- | -------------------------------------------------------------------- |
| `/opt/ciscat/bin`                            | bridge scripts (`ciscat-fleet.py`, `ciscat-scheduler.py`, …)         |
| `/opt/ciscat/benchmarks`                     | CIS benchmark files (licensed, never in the repository)              |
| `/opt/ciscat/license/license.xml`            | CIS-CAT Pro licence, sent to the agents (root, 0600)                 |
| `/opt/ciscat/etc/ciscat-orchestrator.conf`   | settings: API user, password file, `auto_assign`, `keep_default_sca` |
| `/opt/ciscat/etc/manifest-signing.key`       | private signing key (root only, never copied)                        |
| `/opt/ciscat/etc/ciscat-manifest.pub{,.xml}` | public keys for Linux and Windows agents                             |
| `/opt/ciscat/log`                            | scheduler log and one log per job                                    |
| `/opt/ciscat/backup`                         | backups made by every installation                                   |
| `/opt/ciscat/install/<version>`              | unpacked release packages (kept for rollback and audit)              |
| `/var/ossec/etc/lists/ciscat-*`              | exclusions, schedules, status, coverage history (from the dashboard) |
| `/var/ossec/etc/shared/os-*`, `ciscat-*`     | group files published to the agents                                  |
| `/etc/cron.d/ciscat-scheduler`               | scheduler, every 5 minutes                                           |

**Linux agent**: CIS-CAT Pro in `/opt/ciscat/Assessor`, bridge data and results in
`/var/lib/wazuh-ciscat`, bootstrap in `/var/ossec/active-response/bin/ciscat-bootstrap.sh`,
log in `/var/ossec/logs/active-responses.log`.

**Windows agent**: everything under `C:\CIS` (Assessor, `bin`, `run`, `results`), launcher and
bootstrap in `C:\Program Files (x86)\ossec-agent\active-response\bin`, log in
`active-response\active-responses.log` of the agent.

## 2. First installation

Order: master first, then the agents, then the end-to-end test. The release has three packages
and a `SHA256SUMS` file; check every hash before unpacking.

**Master** (see also `packaging/master/README.txt`):

```
install -d -m 0700 -o root -g root /opt/ciscat/install/<version>
cd /opt/ciscat/install/<version>
sha256sum ciscat-master-<version>.zip        # compare with SHA256SUMS
unzip -o ciscat-master-<version>.zip && chmod -R go-w . && chown -R root:root .
cd master && sh ciscat-master-setup.sh --auto-assign
```

The setup asks once for a Wazuh API administrator to create the `ciscat-bridge` API user; that
password is not stored. Expected result: `RESULT: OK`. Copy the CIS benchmarks to
`/opt/ciscat/benchmarks`, each XCCDF with its OVAL and CPE files (`…-oval.xml`,
`…-cpe-oval.xml`, `…-cpe-dictionary.xml`), and the licence to `/opt/ciscat/license/license.xml`,
then run `/opt/ciscat/bin/ciscat-fleet.py apply`. The agents get the benchmarks and the licence
only from the master: the Assessor of the agent packages has empty `benchmarks` and `license`
folders. `apply` warns when a benchmark refers to an OVAL or CPE file that is not there.

**Master in one go** (production): the build kit's `ciscat-prod-<version>.tar.gz` holds the master
package, plugin, CIS benchmarks, license and agent packages; unpack it in
`/opt/ciscat/install/bundle` and run `sh install-prod.sh` (see `packaging/README.md`). It does
the steps above, then `apply`.

**Agents, final packages** (with CIS-CAT Pro, built from the CIS downloads, see
`packaging/README.md`; distributed through Satellite or Ansible):

- Linux and other Unix-like: `tar -xzpf ciscat-agent-linux-<version>-assessor-<a>.tar.gz -C /` as
  root. It lays down `/opt/ciscat/Assessor` and the bootstrap in
  `/var/ossec/active-response/bin`; nothing else to run.
- Windows: `Expand-Archive -Path ciscat-agent-windows-<version>-assessor-<a>.zip -DestinationPath C:\ -Force`
  as Administrator. It lays down `C:\CIS\Assessor` and the launcher and bootstrap in
  `C:\Program Files (x86)\ossec-agent\active-response\bin`.

At its first run the bootstrap checks the Assessor against the package (`Assessor checked against
the agent package` in the Active Response log), moves aside the files of an earlier Assessor and,
on Windows, makes `C:\CIS` writable only by SYSTEM and Administrators.

**Agents without the Assessor in the package** (light packages): unpack
`ciscat-agent-linux-<version>.tar.gz` in `/opt/ciscat/install/<version>` and run
`sh install-linux-agent.sh` in `agent-linux/`; on Windows unpack
`ciscat-agent-windows-<version>.zip` in `C:\CIS\install\<version>` and run
`powershell -ExecutionPolicy Bypass -File .\install-windows-agent.ps1` in `agent-windows\`, as
administrator. Both end with `RESULT: OK` and never install from a home or temporary folder.

**Many agents**: the Ansible role in `packaging/ansible` does the same on Linux and Windows
(WinRM), unpacking a final package or running the installer. See `packaging/README.md`.

**End-to-end test** on one Linux and one Windows agent:

```
# master
cd /opt/ciscat/install/<version>/master
python3 ciscat-e2e-master.py pre <id> <id>
python3 ciscat-e2e-master.py run <id> <id>
# agents, in their package folder
sh ciscat-e2e-linux.sh watch            then   sh ciscat-e2e-linux.sh post
.\ciscat-e2e-windows.ps1 -Step Watch     then   .\ciscat-e2e-windows.ps1 -Step Post
# master
python3 ciscat-e2e-master.py post <id> <id>
```

Every check prints EXPECT / GOT and PASS, FAIL or WAIT. All PASS means the installation is done.

## 3. The signing key

The master signs every package it publishes. Each agent keeps the master's public key the first
time it receives it and from then on only accepts packages signed with that key.

- Show the key and its fingerprint: `ciscat-fleet.py key`.
- Never copy `manifest-signing.key` anywhere. It is not part of backups exported with
  `ciscat-export-config.sh`.
- **Recommended: pin the key at install.** With Ansible, set `ciscat_master_host` (the master,
  as a host of the inventory): the playbook reads the key on the master and installs it with
  each agent, nothing to copy by hand. By hand: put `ciscat-manifest.pub` next to the Linux
  installer or `ciscat-manifest.pub.xml` next to the Windows one.
- Without pinning, an agent keeps the first key it finds in its group files. Those files can be
  written by the `wazuh` user on the master (and on a Linux agent), so whoever controls that
  user before an agent's first run could give it another key. Alert 100953 records each first
  use with the key's sha256: compare it with the master's (`ciscat-fleet.py key`).
- Changing the key: generate a new one on the master (move the old key files away and run
  `ciscat-fleet.py key`), then reinstall the agents with the new public key, or delete the key
  they keep (`/var/lib/wazuh-ciscat/ciscat-manifest.pub`, `C:\CIS\ciscat-manifest.pub.xml`).

## 4. Routine checks

**Weekly** (5 minutes):

1. Dashboard, CIS-CAT page: the scheduler's last tick is less than 10 minutes old and the last
   jobs ended `ok`.
2. Coverage chart: the share of assessed agents is stable. A drop means agents that stopped
   running the checks; the job status lists every agent not reached and why.
3. Wazuh alerts of the `ciscat` group:
   - **100950**: CIS-CAT Pro or its licence missing on an agent.
   - **100951**: an agent refused a file from the master (signature, checksum or destination).
   - **100952**: an agent received a public key different from the one it keeps.
   - **100953**: an agent kept the master key it received (first run without pinning): check
     the sha256 in the alert against the master's.
     100951 and 100952 must never appear in normal operation: treat them as security events.

**Monthly**: `ciscat-fleet.py report` (scores per agent) and a review of the exclusions
(`ciscat-fleet.py exclusions > exclusions-<date>.csv`): each should still have a valid reason,
ticket and owner. Keep the CSV as the review record.

**On the master, quick status**:

```
tail -50 /opt/ciscat/log/ciscat-scheduler.log
/opt/ciscat/bin/ciscat-fleet.py plan          # what apply would do, changes nothing
/opt/ciscat/bin/ciscat-fleet.py assign        # agents that would join an OS group
```

## 5. Updates

| What changes                | What to do                                                                                                                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Bridge (new release)        | Run the master setup of the new package; agents get the new scripts by themselves                                                                                                                                              |
| Launcher or bootstrap       | Roll out the new agent package (by hand or Ansible)                                                                                                                                                                            |
| CIS benchmark (new version) | Copy the file to `/opt/ciscat/benchmarks`; it shows up in the dashboard within the hour                                                                                                                                        |
| CIS-CAT Pro Assessor        | Build the final agent packages from the CIS downloads, load them into Satellite, roll them out (`packaging/README.md`); the licence and the benchmarks stay, the files of the earlier Assessor are moved aside at the next run |
| Licence renewal             | Replace `/opt/ciscat/license/license.xml`, run `ciscat-fleet.py apply`                                                                                                                                                         |

Every master installation makes a backup in `/opt/ciscat/backup`. To go back:
`sh ciscat-bridge-install-<version>.sh --rollback /opt/ciscat/backup/ciscat-bridge-<date>.tgz`.

Each run logs the CIS-CAT version it used (`CIS-CAT version: x.y.z` in the agent's Active
Response log), so agents with an older Assessor are easy to find.

## 6. Common problems

| Symptom                                            | Likely cause and check                                                                                            |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Agent not assessed, job says "platform"            | A Windows benchmark on a Linux agent or the reverse; check the agent's groups                                     |
| Agent not assessed, job says "status disconnected" | Agent disconnected at run time; it runs at the next schedule                                                      |
| Agent not assessed, "in no group of an active …"   | The agent is in no OS group; `ciscat-fleet.py assign` shows where it would go                                     |
| `REFUSED (signature …)` in the agent log           | The agent keeps another master key; see section 3                                                                 |
| `no ciscat-manifest-*.csv` in the agent log        | Group files not synchronised yet; wait a few minutes or restart the agent                                         |
| Results in CIS-CAT but not in the dashboard        | SCA reads them at its next scan (every hour); restart the agent to read them now                                  |
| Alert 100950                                       | Assessor or licence missing on the agent; reinstall the agent package or the licence                              |
| Windows run never starts                           | `shared\ar.conf` on the agent must map `ciscat-assessment0` (check W2 of the e2e test)                            |
| `REFUSED (Assessor file differs from the package)` | The Assessor was changed after unpacking, or unpacked only in part: unpack the agent package again (alert 100951) |
| Two scores for one server                          | The Wazuh default SCA policy is still on; it is switched off at the next `apply` unless `keep_default_sca=yes`    |

For anything else, the end-to-end scripts point to the step that failed.

## 7. Moving to another master

On the old master, `sh ciscat-export-config.sh` exports the benchmarks, exclusions, schedules
and benchmark groups (no password, token, API setting or key). On the new master run the setup
with `--import ciscat-config-<date>.tgz`. The new master has a new signing key: reinstall the
agents with its public key, or delete the key they keep (section 3).
