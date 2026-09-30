# CIS-CAT bridge: dashboard ↔ master data contract

The dashboard and the Wazuh master exchange CIS-CAT exclusions, schedules and status through
Wazuh CDB list files in `/var/ossec/etc/lists/`. The dashboard uses only the Wazuh API
(`GET/PUT /lists/files/{name}`), so no extra service, port or credential is involved and Wazuh
RBAC decides who may change them. The master reads and writes the same files on disk.

The files are not referenced by any `<list>` in `ossec.conf`, so they never reach the
ruleset.

## Line format

Wazuh 4.x accepts a list value only without `:` and `"` (`validate_cdb_list`). Every line is:

```
<key>:<base64url(compact JSON object), no padding>
```

- Keys match `^[A-Za-z0-9._-]{1,128}$`.
- The JSON is UTF-8, has sorted keys, and always carries `"v": 1` (the schema version).
- Lines that do not decode are reported and ignored. They never stop the other lines from being read.
- Keys starting with `_` are metadata, not records (`_meta` in benchmark sheets; `_empty` keeps a
  list file non-empty after its last record is removed). Validators skip them.

## Files and writers

Each file has exactly one writer, so the two sides never overwrite each other.

| File                    | Writer    | Key                                                                                          | Record         |
| ----------------------- | --------- | -------------------------------------------------------------------------------------------- | -------------- |
| `ciscat-exclusions`     | dashboard | `e` + first 16 hex of SHA-1 of `os_key\|scope\|scope_value(lower)\|level\|role(lower)\|rule` | exclusion      |
| `ciscat-schedule`       | dashboard | `j` + 12 hex                                                                                 | job            |
| `ciscat-requests`       | dashboard | `r` + epoch ms + 4 hex                                                                       | request        |
| `ciscat-status`         | master    | see below                                                                                    | status         |
| `ciscat-oskeys`         | master    | os key                                                                                       | OS entry       |
| `ciscat-bench-<os_key>` | master    | rule number, plus `_meta`                                                                    | benchmark rule |

The exclusion key is derived from the record itself, so the same exclusion cannot appear twice.
The master rejects a record whose key does not match it.

## Records

**Exclusion** (`ciscat_store.validate_exclusion`)

| Field                       | Rule                                                                                     |
| --------------------------- | ---------------------------------------------------------------------------------------- |
| `os_key`                    | `^[a-z0-9_]{1,64}$`: the benchmark the rule number belongs to                            |
| `scope`                     | `os`, `global`, `host` or `app_group`                                                    |
| `scope_value`               | `os` → the os key; `global` → `all`; `host` → agent name; `app_group` → Wazuh group name |
| `level`                     | `L1`, `L2`, `NG` or `ALL`                                                                |
| `role`                      | optional profile role (`Server`, `Member_Server`, …); empty = any role                   |
| `rule`                      | CIS number, `^[0-9]+(\.[0-9]+){0,9}$`                                                    |
| `reason`, `ticket`, `owner` | audit text; empty becomes `n/a`                                                          |
| `updated_by`, `updated_at`  | who and when (ISO 8601)                                                                  |

**Job** (`ciscat_store.validate_job`). Times are in the master's local time.

| `type`    | Fields                                                                                   |
| --------- | ---------------------------------------------------------------------------------------- |
| `once`    | `at`: `YYYY-MM-DDTHH:MM`                                                                 |
| `monthly` | `day` 1..31 (a short month uses its last day) or −1..−28 (−1 = last day); `time` `HH:MM` |
| `weekly`  | `weekday` 0..6 (0 = Monday); `time` `HH:MM`                                              |

Common fields:

- `targets`: os keys, or `["*"]` for every active OS;
- `wave_size` (default 50);
- `wave_pause_s` (default 300);
- `enabled`, `label`, `created_by`, `created_at`.

To start a run immediately, use a `run` request rather than a job.

**Request**. The master records processed request keys in `ciscat-status`, and the dashboard
removes old processed requests. Two actions exist:

- `{"action": "apply"}` asks the master to regenerate and publish the policies from the current
  exclusions.
- `{"action": "run", "targets", "wave_size", "wave_pause_s", "label"}` is "Run now". It starts
  right away, after any pending apply, without a time, so the browser and master time zones do
  not matter. Its status is `job-<request key>`.

**Status** (`ciscat-status`, written by the master)

| Key             | Record                                                                                                                      |
| --------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `scheduler`     | `last_tick`, `last_sync`, and the master time zone (`tz`, `utc_offset`) in which job times are read                         |
| `apply`         | `state` (`running`, `ok` or `error`), `request`, `started_at`, `finished_at`, `errors`, `per_os` (combos, checks, excluded) |
| `job-<job key>` | `state`, `last_run`, `next_run`, `sent`, `failed`, `skipped`, `missed`                                                      |
| `requests`      | `processed`: request keys already handled                                                                                   |

**Benchmark** (`ciscat-bench-<os_key>`, written by the master from the XCCDF)

- `_meta`: `os_key`, `benchmark`, `version`, and `profiles`, the profile columns such as `L1_Server`.
- `<rule>`: `t` (title), `p` (profile columns that select the rule), `m` (manual: `true` for
  rules without an automated check).

**OS entry** (`ciscat-oskeys`): `group`, `policy_id`, `benchmark`, `version`, `active`.

## Scheduling

Cron runs `ciscat-scheduler.py` every 5 minutes. On each tick:

1. It runs a job once when one or more of its scheduled times fall in (last tick, now].
2. Times missed by more than 6 hours (the scheduler was not running) are reported as `missed`
   and not run late.
3. A run triggers the agents of the targeted OS groups in waves (`wave_size`, then
   `wave_pause_s`), in a separate process, so a long run does not block later ticks.
