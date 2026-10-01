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

`sync` lists the others as skipped (network devices, cloud services, browsers): they have no Wazuh
agent to run on.

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
- **Status:** the tab shows the scheduler heartbeat, the last apply per OS, recent runs, and the
  disconnected agents that were skipped.

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

## Commands on the master

```
ciscat-fleet.py sync|plan|apply|report
ciscat-fleet.py trigger --targets rhel7,windows_server_2025 --wave-size 50 --wave-pause 300
ciscat-scheduler.py            # what cron runs every 5 minutes
```

Logs are in `/opt/ciscat/log/`: the scheduler log, and one log per job.

## Tests

```
python3 -m unittest discover -s tools/ciscat-bridge/tests
CISCAT_TEST_BENCHMARKS=<folder with CIS XCCDFs> python3 -m unittest tests.test_fleet_integration
python3 tools/ciscat-bridge/tests/make_vectors.py   # after a contract change; checked by Jest too
```
