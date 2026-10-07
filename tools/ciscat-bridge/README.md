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
  chart above the tabs.
- **Status:** the tab shows the scheduler heartbeat, the last apply per OS, recent runs, and the
  disconnected agents that were skipped.

## Terraform

`terraform/` holds a module that installs the bridge and the dashboard plugin on existing Wazuh
4.14 hosts, writes the API credentials from Vault, and owns the `baseline-*` groups: their whole
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
  with `--rollback <file>`: the `ciscat-*` lists present at that point are kept (they hold what was
  saved in the dashboard since the backup), and only missing ones are restored. When the
  installation itself fails, the backup is restored at once, exactly.
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

API credentials come from `api_user` and `api_pass_file` in
`/opt/ciscat/etc/ciscat-orchestrator.conf` (mode 600). They are never passed on the command line:
`--password` still works but is deprecated.
The API certificate is not verified by default (the local manager API, self-signed); set
`api_ca=<CA file>` in the same file to verify it.

## Commands on the master

```
ciscat-fleet.py sync|plan|apply|report
ciscat-fleet.py trigger --targets rhel7,windows_server_2025 --wave-size 50 --wave-pause 300
ciscat-scheduler.py            # what cron runs every 5 minutes
```

Logs are in `/opt/ciscat/log/`: the scheduler log, and one log per job. Only one `apply` runs at a
time: a second one (by hand, from the installer or the scheduler) waits for it.

On the agents, `ciscat-bootstrap.sh` installs the manifest's files only into the Assessor's
`benchmarks` folder, `/var/lib/wazuh-ciscat` and `active-response/bin/ciscat-refresh.sh`;
`ciscat-refresh.sh` reads `refresh.conf` as `KEY="value"` data (it is not sourced) and runs one
assessment at a time.

## Changes

- **2.2.8:** scheduler: a job set in the hour repeated when daylight saving time ends runs once, a
  fast run keeps its result, and handled requests never run again. Apply: one at a time, files in
  the shared folders replaced in one step, missing benchmark files reported as errors, combo
  groups made by hand left alone. Trigger renews its API token during long runs. Agents: an empty
  or inconsistent report no longer replaces the results; bootstrap destinations limited;
  `refresh.conf` not sourced; Windows uses only the report of the current run. Installer: restores
  the backup when it fails. Terraform: `wazuh_major = 5` refused (not supported yet).
  Benchmarks are read by one XML parser (`ciscat_xccdf.py`, a DOCTYPE is refused): titles show
  `&` instead of `&amp;`, policies are generated several times faster, and the custom XCCDF is
  unchanged. `trigger` waves default to 50 agents and 300 s, as in the schedules. Run logs on
  Linux agents are limited to the last 30.

## Tests

```
python3 -m unittest discover -s tools/ciscat-bridge/tests
CISCAT_TEST_BENCHMARKS=<folder with CIS XCCDFs> python3 -m unittest tests.test_fleet_integration
python3 tools/ciscat-bridge/tests/make_vectors.py   # after a contract change; checked by Jest too
```
