# CIS-CAT bridge: SWIFT CSP and audit evidence

How the bridge supports the SWIFT Customer Security Programme and other audits, what evidence it
produces, and where its limits are. It is written for the people who prepare an assessment and
for the assessors themselves.

Control numbers and titles refer to the **SWIFT Customer Security Controls Framework (CSCF)
v2026**, published by SWIFT on 1 July 2025. The framework changes every year: before each
assessment, check the numbering, the mandatory/advisory status and the wording against the
current CSCF document on the SWIFT Knowledge Centre. Nothing here replaces that document or the
assessor's judgement.

## 1. What the bridge is, for an assessor

- **A configuration assessment control.** It measures each server against its CIS Benchmark
  (an industry hardening baseline), on a schedule, and records the result in Wazuh. It does not
  change the server configuration.
- **A documented baseline with documented deviations.** The applied baseline is the CIS
  Benchmark Level 1 profile of the server's operating system, minus the checks excluded in the
  dashboard. Every exclusion carries a reason, a ticket and an owner, and is stored with who
  changed it and when.
- **Evidence over time, not only a snapshot.** Job status, per-agent results and a daily coverage
  history (kept 400 days) show that the control operated during the assessment period.

## 2. Scope and architecture considerations

If any server in the SWIFT secure zone (for example the messaging or communication interface,
the jump servers, or the operator PCs, depending on the architecture type) runs a Wazuh agent
assessed by the bridge, the bridge becomes part of the management path into the secure zone. An
assessor will ask about it. These are the facts to give:

| Question                                              | Answer                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can the Wazuh master run code on secure-zone servers? | Yes: it sends an Active Response that runs the bridge scripts as root or SYSTEM. This is why the controls below exist.                                                                                                                                                                                                            |
| How is that code protected?                           | Every package is listed in a manifest signed by the master (RSA 3072, SHA-256). The agent verifies the signature with the master's public key it keeps, checks each file's SHA-256 in a root/Administrators-only staging folder, and installs only to a fixed set of folders. Anything else is refused and logged (alert 100951). |
| Who can sign?                                         | Only root on the Wazuh master: the private key is in `/opt/ciscat/etc`, mode 0600, never exported.                                                                                                                                                                                                                                |
| Who can trigger a run?                                | The `ciscat-bridge` API user (least-privilege role: agent read, group assignment, Active Response, SCA read) and dashboard users allowed to write the `ciscat-*` lists.                                                                                                                                                           |
| Network direction                                     | Agents connect to the manager (agent-initiated, TCP 1514). Nothing connects into the agents.                                                                                                                                                                                                                                      |
| What does the run read or send?                       | Configuration settings of the server, checked locally. Results stay inside Wazuh. No SWIFT business data is read.                                                                                                                                                                                                                 |
| Can the run break the server?                         | It only reads the configuration. CIS-CAT Pro does not remediate.                                                                                                                                                                                                                                                                  |

Points to settle with the assessor and to record in the architecture documentation:

- whether the Wazuh manager is treated as a component of the secure zone or as a general IT
  system with an administrative path into it, and which controls then apply to the manager itself
  (hardening, privileged access, logging, its own patching);
- that the manager's signing key and root access are governed like other privileged credentials
  of the secure zone;
- that secure-zone agents get the master's public key pinned at installation (Ansible with
  `ciscat_master_host`, or `--pubkey` / `-PublicKey`). Without pinning, an agent keeps the first
  key found in its group files, which the `wazuh` user of the master can write: an attacker
  holding that account before an agent's first run could have it accept their key. Alert 100953
  records every key kept this way, with its sha256.

## 3. CSCF v2026 controls the bridge supports

"Supports" means the bridge produces evidence for part of the control. No control below is fully
met by the bridge alone.

| CSCF control                                         | How the bridge supports it                                                                                                                                                                                      | Limits                                                                                                                                                                                                                                              |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **2.3 System Hardening**                             | Main control supported. Measures each in-scope server against the CIS Benchmark of its OS, on a schedule; deviations recorded with reason, ticket and owner; results per check.                                 | Hardening itself is done by the server owners. The CSCF guidance and v2026 Windows additions (e.g. restrictions on WMI and PowerShell) must be compared with the benchmark's checks: what the benchmark does not check, the bridge does not report. |
| **1.2 Operating System Privileged Account Control**  | Benchmark checks on administrator accounts, UAC, sudo, root login, privilege rights.                                                                                                                            | Does not review who holds privileged accounts or how they are used.                                                                                                                                                                                 |
| **4.1 Password Policy**                              | Benchmark checks on the OS password and lockout settings.                                                                                                                                                       | Local and domain policy settings only; not application passwords or password management processes.                                                                                                                                                  |
| **6.4 Logging and Monitoring**                       | Benchmark checks that audit logging (auditd, Windows audit policy, log sizes) is configured. The bridge's own events (missing Assessor or licence, refused file, foreign key) raise Wazuh alerts 100950–100952. | Checks configuration, not that logs are collected, reviewed and retained.                                                                                                                                                                           |
| **6.1 Malware Protection**                           | On Windows, benchmark checks on Microsoft Defender settings.                                                                                                                                                    | Settings only; not detection quality or coverage of other anti-malware products.                                                                                                                                                                    |
| **2.2 Security Updates**                             | A few benchmark checks on update settings and package versions.                                                                                                                                                 | Not patch management: missing patches are reported by the vulnerability detection or patching tools.                                                                                                                                                |
| **2.7 Vulnerability Scanning**                       | Complementary configuration view, useful next to the vulnerability scan.                                                                                                                                        | Not a vulnerability scan; does not replace it.                                                                                                                                                                                                      |
| **1.4 Restriction of Internet Access**               | Some benchmark checks on host firewall and network settings.                                                                                                                                                    | Host settings only; internet access is enforced by network controls.                                                                                                                                                                                |
| **7.x Plan for Incident Response / Risk assessment** | Not covered.                                                                                                                                                                                                    | —                                                                                                                                                                                                                                                   |

The bridge also follows good practice that an assessor looks for in any tool with a path into the
secure zone: integrity of the code it distributes (signed manifests), least privilege for its API
user, change records (versioned releases with checksums) and alerting on its own failures.

## 4. Evidence pack

What to hand over, where it comes from and what it proves. "Period" is the assessment period,
usually the twelve months before the attestation.

| #   | Evidence                                                           | Source                                                                                   | Proves                                                    |
| --- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| E1  | Applied baseline per OS: benchmark name and version, profile       | Dashboard, CIS-CAT page; `ciscat-fleet.py plan`                                          | Which standard is applied (design)                        |
| E2  | Exclusion register with reason, ticket, owner, who and when        | CIS-CAT page, "Export register (PDF)" (in Reporting); `ciscat-fleet.py exclusions` (CSV) | Deviations are documented and approved (design)           |
| E3  | Schedules                                                          | Dashboard, CIS-CAT page (`ciscat-schedule`)                                              | The control is planned to run regularly (design)          |
| E4  | Job history: start, end, agents reached, agents skipped and why    | Dashboard job status (`ciscat-status`); `/opt/ciscat/log/ciscat-job-*.log`               | The control ran (operating effectiveness)                 |
| E5  | Coverage history, day by day                                       | Dashboard coverage chart, "Show data" table (`ciscat-history`, 400 days)                 | It ran throughout the period, and for how many servers    |
| E6  | Results per secure-zone server: passed, failed, score, end of scan | Dashboard, Configuration Assessment, "Export formatted"; `ciscat-fleet.py report`        | Current compliance of each in-scope server                |
| E7  | Follow-up of failed checks                                         | Change or incident tickets referenced from the results or the exclusions                 | Failures lead to remediation or to a documented exception |
| E8  | Raw CIS-CAT reports (ARF/CSV) for sampled servers                  | Agent: `/opt/ciscat/Assessor/reports`, `C:\CIS\Assessor\reports`                         | Independent evidence from the assessment tool itself      |
| E9  | Agent run log with signature check and CIS-CAT version             | Agent Active Response log (`signature OK`, `CIS-CAT version: x.y.z`)                     | Integrity of what ran, and which tool version             |
| E10 | Alerts 100950, 100951, 100952 over the period, and their handling  | Wazuh alerts, group `ciscat`                                                             | Failures of the control are detected and followed up      |
| E11 | Access to the bridge: API role and policies, dashboard roles       | Wazuh API (`ciscat-bridge` role), dashboard security settings                            | Who can change the baseline or trigger runs               |
| E12 | Release and change records: version, checksums, test results       | Code repository (signed-off commits), release attachments with `SHA256SUMS`, e2e outputs | The tool itself is under change control                   |

Keep screenshots dated and with the host name visible. A screenshot shows a state; E4 and E5 are
what show the control operating over time.

## 5. Test procedures for the assessor

1. **Design**: inspect E1–E3. Pick three exclusions and trace each to its ticket and approval.
2. **Operation over the period**: inspect E5 for the whole period and E4 for a sample of
   scheduled runs. Gaps in coverage must be explained (maintenance, decommissioned servers).
3. **Reperformance on a sample**: for one secure-zone server, start a run from the dashboard
   ("Run now" on that agent), then compare the dashboard result with the raw CIS-CAT report on
   the server (E8) for a few checks, passed and failed.
4. **Integrity of the distributed code**: on the sampled server, inspect the Active Response log
   for `signature OK` and the absence of `REFUSED` (E9); check that the kept public key matches
   the master's (`ciscat-fleet.py key` on the master, the e2e `pre` check on the agent).
5. **Follow-up**: for a sample of failed checks, find the remediation change or the exclusion
   (E7).
6. **Access**: inspect E11 and confirm that only the intended people can change exclusions and
   schedules.

## 6. Other frameworks

The same evidence pack serves other audits. The mapping below is a starting point; check the
current text of each framework.

| Framework                                                       | Requirement areas the bridge supports                                                                                                                                                                                                                    |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ISO/IEC 27001:2022, Annex A                                     | 8.9 Configuration management (main), 8.8 Management of technical vulnerabilities (partial), 8.15/8.16 Logging and monitoring (configuration checks, alerts), 5.36 Compliance with policies and standards, 8.32 Change management (for the bridge itself) |
| FINMA Circular 2023/1 (operational risks and resilience, banks) | ICT risk management: secure configuration baselines, their monitoring and documented deviations; evidence of operation over time for internal and regulatory audit                                                                                       |
| CIS Critical Security Controls v8                               | Control 4 (Secure Configuration of Enterprise Assets and Software)                                                                                                                                                                                       |
| NIST Cybersecurity Framework 2.0                                | PR.PS (platform security: configuration management), DE.CM (continuous monitoring)                                                                                                                                                                       |
| PCI DSS v4.0 (where applicable)                                 | Requirement 2.2 (system components configured and managed securely)                                                                                                                                                                                      |

## 7. Questions to expect, and short answers

- _Which standard do you harden against?_ CIS Benchmarks, Level 1, per operating system and
  version; the list is on the CIS-CAT page (E1).
- _How do you handle checks you cannot apply?_ Exclusions with reason, ticket and owner (E2). The
  approval and the periodic review of the exclusions are part of our process: show the tickets
  and the review record.
- _How often is it checked?_ As scheduled (E3); coverage over the period in E5.
- _How do you know every secure-zone server is included?_ New agents join the group of their OS
  automatically; the coverage chart counts every agent of the OS groups, including disconnected
  ones (E5).
- _How do you know the results are genuine?_ The packages are signed, the run log shows the
  signature check and the CIS-CAT version, and the raw CIS-CAT report on the server can be
  compared with the dashboard (E8, E9).
- _What happens when a check fails?_ It stays failed in the dashboard until the server is fixed or
  an exclusion is approved (E7).

## 8. Known limits

- The bridge reports what the CIS Benchmark checks. Requirements outside the benchmark need other
  evidence.
- Checks marked "manual" in the benchmark are not scored automatically.
- A server without the Wazuh agent, or outside every OS group, is not assessed. The coverage
  chart only counts agents of the OS groups; the inventory of in-scope servers must come from the
  SWIFT architecture documentation.
- The Wazuh default SCA policies are switched off on the assessed servers, so the dashboard shows
  one score per server: the CIS-CAT one.
