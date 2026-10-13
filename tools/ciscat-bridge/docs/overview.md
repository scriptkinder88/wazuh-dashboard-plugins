# CIS-CAT bridge: overview

This page is for anyone who needs to know what the bridge does and who looks after what, without
the technical detail. The operations guide (`operations.md`) has the commands, and
`compliance.md` explains how the results are used in audits.

## What it is for

Every server should be configured according to a hardening standard: no unnecessary services,
strong password rules, audit logging switched on, and so on. The standard we use is the
**CIS Benchmark** of each operating system (for example "CIS Red Hat Enterprise Linux 7" or "CIS
Microsoft Windows Server 2025"). Each benchmark is a list of a few hundred checks.

**CIS-CAT Pro** is the tool from the Center for Internet Security that checks a server against its
benchmark. **Wazuh** is our security monitoring platform: every server runs a Wazuh agent that
reports to the Wazuh manager, and the results are shown in the Wazuh dashboard.

The bridge connects the two. It lets us run CIS-CAT Pro on all servers from the Wazuh dashboard,
on a schedule, and shows the results there next to the rest of the security data.

## What you see

In the Wazuh dashboard, under **Configuration Assessment**:

- **For each server**: the benchmark of its operating system, how many checks pass and fail, the
  score, and each check with its result.
- **CIS-CAT page**: the benchmarks in use, the exceptions agreed for them, the schedules, and a
  button to run the checks now.
- **Coverage chart**: the share of servers checked in the last 35 days, day by day.

## Exceptions

Not every check can be applied to every server. A check that would break an application, or that
is covered by another control, can be excluded. Each exclusion is recorded in the dashboard with
the reason, a ticket number and an owner, and applies to one operating system, one server, or a
group of servers. Excluded checks are not run and do not count in the score. The list of
exclusions is the register of accepted deviations from the standard.

## How it works, in five steps

1. An operator chooses the benchmarks, the exceptions and the schedule in the dashboard.
2. The Wazuh manager prepares, for each operating system, the benchmark minus the exceptions, and
   publishes it to the servers of that system. Every package it publishes is digitally signed.
3. At the scheduled time the manager asks the servers to run the check.
4. Each server verifies the signature, runs CIS-CAT Pro, and hands the results to its Wazuh agent.
5. The results appear in the dashboard within the hour.

A new server joins the right group by itself, from the operating system it reports to Wazuh, and
is checked at the next run.

## Who does what

| Who                        | Responsibility                                                                         |
| -------------------------- | -------------------------------------------------------------------------------------- |
| Security / compliance team | Decides the benchmarks and the schedules, approves the exceptions, reads the results   |
| Wazuh administrator        | Installs and updates the bridge on the manager, watches its status, renews the license |
| Server owners              | Install the bridge package on new servers (or via Ansible), fix the failed checks      |
| Auditors                   | Receive the evidence described in `compliance.md`                                      |

## What it does not do

- It does not change the servers' configuration. It only checks and reports. Fixing a failed
  check is a separate change, done by the server owner.
- It does not replace vulnerability scanning or patch management. Some checks look at update
  settings, but missing patches are found by other tools.
- Network devices, cloud services and macOS are not covered: they have no Wazuh agent to run
  CIS-CAT Pro on.

## Licences

CIS-CAT Pro and the CIS benchmarks are licensed by the Center for Internet Security. They are
never stored in the code repository. The licence file is kept on the Wazuh manager and reaches the
servers with the signed packages. When it is renewed, the Wazuh administrator replaces one file.
