# CIS-CAT bridge

This bridge runs CIS-CAT Pro assessments on Wazuh agents and reports the results as Wazuh SCA
policies, and it is managed from the dashboard. The **CIS-CAT** tab of Configuration Assessment
edits the exclusions and the schedules. The manager applies them.

CIS-CAT Pro and the CIS benchmarks are licensed. They are not part of this repository or of the
installer:

- **The Assessor** is provisioned on each agent: `/opt/ciscat/Assessor` on Linux,
  `C:\Program Files (x86)\ciscat` on Windows.
- **The benchmarks** stay in `/opt/ciscat/benchmarks` on the master.

Every CIS benchmark in that folder is an OS of the bridge, one per product and version: copy a
benchmark there and, within the hour (or at the next `ciscat-fleet.py sync`), it appears in the
dashboard with its name and version, for example
`CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0-xccdf.xml` becomes "Red Hat Enterprise Linux 9
v2.0.0" (key `rhel9_v2_0_0`). Two versions of the same benchmark are two entries, each with its own
exclusions.

In the CIS-CAT tab, **Applies to group** chooses the Wazuh group whose agents get the benchmark
(by default `os-<key>`); **Save and apply** has the master publish it to that group. Apply and runs
skip an OS until its group exists. An entry in `/opt/ciscat/etc/os-library.json` keeps its
settings (for example `"active": false`; choosing a group in the dashboard activates it again), and one whose benchmark file is missing follows the
newest version of the same product in the folder.

The bridge assesses the Level 1 profile of each benchmark, preferring the Server, Member Server or
Database Engine role. Benchmarks without `Level 1 - <role>` profiles are handled too:

- STIG benchmarks with `SEVERITY_CAT_I/II/III` profiles (`MS_`/`DC_` on Windows Server): every
  category together, role `STIG` (`Member_Server_STIG` on Windows Server);
- `Level_1` or `Level_1_L1` (Apache, Tomcat, Windows 11): that profile, role `Default`;
- `Level_1-_<Role>` (MongoDB): that profile.

`sync` lists as skipped the benchmarks of platforms without a Wazuh agent (network devices,
managed Kubernetes, cloud and SaaS services, ESXi), macOS (not handled by the bridge) and those
without a Level 1 or STIG profile. GPO benchmarks (Firefox ESR, VS Code) are Windows ones.

## How it works

```
dashboard (CIS-CAT tab) ──Wazuh API /lists/files──▶ etc/lists/ciscat-*  (CONTRACT.md)
                                                         │
master: cron */5 ciscat-scheduler.py ──▶ ciscat-fleet.py apply / trigger
   ├─ os-<os> group:               custom XCCDF (OS + global exclusions), companions, scripts
   └─ ciscat-<os>-<combo> groups:  the SCA policy for agents sharing the same agent/group exclusions
agent: Active Response → Assessor → flatten file → SCA policy → results in Wazuh
```

- **Benchmark files:** the `os-<os>` group carries the custom XCCDF and, under their original
  names, the benchmark's OVAL and CPE files (`-oval.xml`, `-cpe-oval.xml`,
  `-cpe-dictionary.xml`): the XCCDF checks reference them by file name. The agent copies them
  into the Assessor's `benchmarks` folder (`/opt/ciscat/Assessor/benchmarks`, or
  `C:\Program Files (x86)\ciscat\benchmarks`) before the assessment, so an agent does not need
  the benchmark in its own CIS-CAT bundle.
- **Exclusions:** the scope is `os`, `global`, `host` (agent name) or `app_group` (Wazuh group).
  Every exclusion records a reason, a ticket, an owner, who made it and when.
- **Schedules:** a job runs once, monthly (day N, or N days before the month end) or weekly, in
  waves of N agents with a pause between waves. "Run now" starts a run right away. Times are in
  the manager's time zone. A run missed by more than 6 hours is reported, not run late.
- **Coverage trend:** once a day the scheduler records, per OS, how many agents of its group have a
  scan of the CIS-CAT policy from the last 35 days (`ciscat-history`). The tab shows it as a line
  chart above the tabs. On Wazuh 5.0, which keeps no scan time, it counts the agents that have
  results of the CIS-CAT policy.
- **Status:** the tab shows the scheduler heartbeat, the last apply per OS, recent runs, and the
  disconnected agents that were skipped.

## Terraform

`terraform/` holds a module that installs the bridge and the dashboard plugin on existing hosts, writes
the API (and 5.0 indexer) credentials from Vault, and owns the `baseline-*` groups: their whole
`agent.conf` and the agents listed for them, written with `ciscat-fleet.py baseline --file`.
Everything else stays in the dashboard. See `terraform/README.md`.

## Production: one command

`python3 tools/ciscat-bridge/installer/build.py` writes `dist/ciscat-bridge-install-<version>.sh`
and its `.sha256`. The build is reproducible: the same sources always give the same checksum. The
script is self-contained, so copy its text to the host and run it as root. Nothing else has to be
transferred, and the master needs no network access.

On the master:

```
sh ciscat-bridge-install-<version>.sh            # install/update, migrate, sync, plan (agents untouched)
sh ciscat-bridge-install-<version>.sh --apply --restart-manager
```

What it does:

- It refuses a cluster worker and a damaged copy (the payload SHA-256 is checked before anything
  changes).
- It backs up everything it touches to `/opt/ciscat/backup/ciscat-bridge-<date>.tgz`. Restore it
  with `--rollback <file>`.
- It installs the scripts into `/opt/ciscat/bin` and `/opt/ciscat/agent/active-response`, and the
  rule into `etc/rules/ciscat_rules.xml`. A rule ID that is already in use is refused, and the
  ruleset is tested with `wazuh-analysisd -t`.
- It creates `/opt/ciscat/etc/os-library.json` from the OS table of the `ciscat-fleet.py` in
  place. It does this only once: later updates keep the site's `active` flags.
- It migrates `/opt/ciscat/tailoring/exclusions/*.csv` to the dashboard list once. Scopes written
  by the old HTML composer are mapped: `group` → `app_group`, and `host_list` → one `host` each.
- It comments out the `ciscat-orchestrator.sh` cron entries and installs
  `/etc/cron.d/ciscat-scheduler`.
- It runs `sync` (benchmark sheets for the dashboard) and `plan`. `apply` runs only with `--apply`.

Running the same version again changes nothing.

On the dashboard host, the plugin comes from the internal repository. Its checksum is required:

```
sh ciscat-bridge-install-<version>.sh --plugin-url https://<internal-repo>/wazuh-<version>.zip \
   --plugin-sha256 <sha256 of the zip> --restart-dashboard
```

On a host that is both master and dashboard, one run does both.

API credentials come from `api_pass_file` in `/opt/ciscat/etc/ciscat-orchestrator.conf` (mode
600). They are never passed on the command line.

## Wazuh 5.0

The bridge detects Wazuh 5.0 by `/var/wazuh-manager` (`CISCAT_PLATFORM=4|5` overrides it,
`bin/ciscat_platform.py`). Agents, exclusions, combos, waves and schedules work as on 4.x; what
changes is where the data lives and how a run reaches the agents.

|                           | Wazuh 4.x                                         | Wazuh 5.0                                                                                          |
| ------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Manager                   | `/var/ossec`, files owned by `wazuh`              | `/var/wazuh-manager`, files owned by `wazuh-manager`                                               |
| Dashboard data            | CDB lists in `etc/lists/ciscat-*`                 | one document per list in the hidden index `wz-dashboard-store-ciscat` (CONTRACT.md)                |
| Runs                      | `PUT /active-response`                            | trigger documents in `wazuh-findings-v5-ciscat`, turned into Active Responses by Alerting monitors |
| Report                    | `GET /sca/{agent}`                                | the `wazuh-states-sca*` index                                                                      |
| SCA policy                | `title`, `cis_csc_v8` and `cis_family` compliance | `name`, no compliance block (`xccdf_to_sca_policy.py --format 5`)                                  |
| Missing CIS-CAT Pro alert | `etc/rules/ciscat_rules.xml`                      | `rules/ciscat-not-found.sigma.yml`, imported by hand                                               |

### Install on a 5.0 master

The bridge reads and writes the indexer with its own user. Give it a user whose role can read and
write `wz-dashboard-store-ciscat`, create documents in `wazuh-findings-v5-ciscat`, read
`wazuh-states-sca*`, and manage Notifications channels and Alerting monitors. The first run needs
the connection settings:

```
sh ciscat-bridge-install-<version>.sh --indexer-url https://127.0.0.1:9200 \
   --indexer-user ciscat-bridge --indexer-password-file /root/ciscat-indexer.pass \
   --indexer-ca /etc/wazuh-indexer/certs/root-ca.pem
```

The installer writes `/opt/ciscat/etc/indexer.json` and copies the password to
`/opt/ciscat/etc/indexer.pass` (both mode 600); later runs reuse them. It reaches the indexer before
it changes anything, refuses a cluster worker (`<node_type>worker</node_type>` in
`etc/wazuh-manager.conf`), skips the XML rule and the `wazuh-analysisd -t` test, and creates, when
missing:

- the store index (hidden, one shard, the dashboard's mapping);
- four Active Response channels (`config_type: active_response`, stateless, location `local`):
  `ciscat-bootstrap-linux` → `ciscat-bootstrap.sh`, `ciscat-refresh-linux` → `ciscat-refresh.sh`,
  `ciscat-bootstrap-windows` → `ciscat-bootstrap.cmd` (`--windows-bootstrap-executable` changes
  it), `ciscat-assessment-windows` → `ciscat-assessment.cmd`;
- one `active_response_monitor` per channel with the same name, every minute, on
  `wazuh-findings-v5-ciscat*`, with the query `event.action:"<name>"`.

Channels and monitors are matched by name and put back when they differ, so running the installer
again changes nothing. A rollback restores the files; the index, channels and monitors stay.

### Runs

`ciscat-fleet.py trigger` writes, per wave, one document per agent with
`event.action: <ar_bootstrap>`, waits `CISCAT_AR_GAP` seconds (90 by default on 5.0, because the
monitors run every minute), then one with the assessment action. The monitor of the action
matches the document and the manager runs the channel's executable on the agent of the document
(`wazuh.agent.id`). `ar_*` values of `os-library.json` written for 4.x (`!ciscat-refresh-linux0`,
…) are read as the 5.0 action names above, another `!command` as the default action of its family;
any other value is taken as the name of a channel and monitor set up on site.

The 5.0 policy keeps the CIS number at the start of each check name; the CIS Controls v8 and CIS
family values of the 4.x policy are not 5.0 compliance keys and are left out.

### CIS-CAT Pro missing alert

Import `/opt/ciscat/rules/ciscat-not-found.sigma.yml` as a custom rule through the Wazuh indexer
content manager (Wazuh dashboard, rules of the content manager: create a custom Sigma rule from
the file, then enable it). It matches the `CIS-CAT Pro not found on <host>` line that the agent
scripts write to `active-responses.log`.

### To verify on a real Wazuh 5.0 manager

The 5.0 support is tested against fakes of the Wazuh API and of the indexer only. These points
come from the 5.0 sources, not from a running 5.0 cluster, and must be checked before production:

1. **Channel and monitor creation**: the payloads above are accepted (`active_response` channel,
   `active_response_monitor` with a document-level trigger on `wazuh-findings-v5-ciscat*`), and
   the monitor search by `monitor.name` finds them on the second run.
2. **Trigger documents**: `wazuh-findings-v5-ciscat` is created as a data stream by the
   `wazuh-findings-v5*` template and accepts the fields the bridge writes (strict mapping).
3. **Dispatch**: the manager picks the alerts up from `wazuh-active-responses` (every 30 s) and runs
   the executable on the agent of the document, with the 90 s gap enough between bootstrap and
   assessment; on Windows, that `ciscat-bootstrap.cmd` is the bootstrap script the 4.x
   `ciscat-bootstrap` command ran (it is not part of the bridge).
4. **`ciscat-refresh.sh` without splay**: execd is the script's parent process (`wazuh-execd`),
   which is how the script tells an Active Response from a scheduled run on 5.0.
5. **SCA results**: `wazuh-states-sca*` has one document per agent and check with the fields
   `wazuh.agent.id` (same id as the server API), `policy.id` and `check.result`
   (`Passed`, `Failed`, `Not applicable`) as keyword fields, which `report` aggregates.
6. **SCA policy**: a 5.0 agent loads the remote policy from the combo group (`name` fields, no
   compliance block, `f:` rules only) and reports it under the same policy id.
7. **Sigma rule**: the content manager accepts the rule and `active-responses.log` lines reach it
   in `event.original`.
8. **Indexer role**: the minimum permissions of the bridge user listed above.

## Commands on the master

```
ciscat-fleet.py sync|plan|apply|report
ciscat-fleet.py trigger --targets rhel7,windows_server_2025 --wave-size 50 --wave-pause 300
ciscat-scheduler.py            # what cron runs every 5 minutes
```

Logs are in `/opt/ciscat/log/`: the scheduler log, and one log per job. On Wazuh 5.0 `trigger` and
`report` use the indexer configuration as well as the API credentials.

## Tests

```
python3 -m unittest discover -s tools/ciscat-bridge/tests
CISCAT_TEST_BENCHMARKS=<folder with CIS XCCDFs> python3 -m unittest tests.test_fleet_integration
python3 tools/ciscat-bridge/tests/make_vectors.py   # after a contract change; checked by Jest too
```
