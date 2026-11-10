[README-revised.md](https://github.com/user-attachments/files/34630900/README-revised.md)
# Active Directory Authentication Monitoring Lab

I built this lab to practise collecting and investigating Windows authentication events in an Active Directory environment. It uses PowerShell to collect Security log events from a domain controller and a Windows client, export the relevant fields to CSV, and look for repeated failed logons and possible password-spray activity.

The repository contains the collection scripts, two detection scripts, the test runner, investigation notes and screenshots from the lab.

## What it does

- Collects selected Windows Security events from the domain controller and client.
- Exports the event details into a consistent CSV format.
- Detects repeated failures against the same account within a configurable time window.
- Looks for failures against multiple accounts from one source IP within a configurable time window.
- Exports detection results to CSV for review.
- Tests the detection rules against synthetic data, including boundary cases and scenarios that should not trigger an alert.

## Lab environment

| Component | Configuration |
|---|---|
| Domain | `lab.local` |
| Domain controller | `DC01` — Windows Server 2025 |
| Client | `CLIENT01` — Windows 11 Enterprise Evaluation |
| Virtualisation | VMware Workstation, VMnet8 NAT |
| Domain controller IP | `192.168.183.10` |
| Client IP | `192.168.183.130` |
| Scripting | Windows PowerShell 5.1 / PowerShell 7 on Windows |

The IP addresses are private addresses from this lab's VMware NAT network. Change them to match your own environment if you recreate the setup.

## Repository layout

```text
AD-Authentication-Monitoring-Lab/
├── README.md
├── LICENSE
├── scripts/
│   ├── Get-AuthEvents.ps1
│   ├── Export-AuditPolicySnapshot.ps1
│   ├── Detection.Common.ps1
│   ├── Detect-RepeatedFailedLogons.ps1
│   └── Detect-PasswordSpray.ps1
├── tests/
│   └── Invoke-DetectionTests.ps1
├── docs/
│   ├── Test-Summary.csv
│   ├── architecture.md
│   ├── detection-logic.md
│   ├── investigation-template.md
│   ├── lab-journal.md
│   ├── release-checklist.md
│   └── runbook.md
├── sample-data/
│   └── README.md
└── evidence/
    └── screenshots/
```

Keep local event exports and alert reports in an `output/` directory in the repository. It is excluded from Git, so raw event exports and machine-specific results are not included in the repository. Synthetic test output under `tests/results/` is excluded as well.

## Requirements

- A Windows Server domain controller and a domain-joined Windows client.
- Windows PowerShell 5.1 or later.
- An account with permission to read the local Security event log.
- Administrator rights when changing audit policy.
- The relevant audit subcategories enabled for the events you want to collect.

## 1. Configure Windows auditing

I configured Advanced Audit Policy through Group Policy and checked the effective policy on both machines. The settings to review for this lab are:

- **Logon/Logoff → Audit Logon:** Success and Failure.
- **Account Logon → Audit Credential Validation:** Success and Failure, for NTLM credential validation.
- **Account Logon → Audit Kerberos Authentication Service:** Success and Failure, on domain controllers where Kerberos ticket activity is being monitored.

After applying policy, check the effective settings on each machine:

```powershell
auditpol /get /category:*
```

An event not appearing in an export does not, by itself, mean the activity did not happen. Check the audit subcategory, event ID, time range and Security log retention before drawing that conclusion.

## 2. Collect authentication events

Run the collector locally on each machine in an elevated PowerShell session. Copy the repository's `scripts` folder to each VM first. The examples below assume it is at `C:\Users\Public\Documents\Cyberlab\Scripts`.

On **CLIENT01**, collect interactive and network logon events:

```powershell
Set-Location 'C:\Users\Public\Documents\Cyberlab\Scripts'

.\Get-AuthEvents.ps1 `
  -DaysBack 7 `
  -EventIds 4624,4625 `
  -OutputPath 'C:\Users\Public\Documents\Cyberlab\Client-Auth-Events.csv'
```

On **DC01**, collect domain authentication and account lockout events:

```powershell
Set-Location 'C:\Users\Public\Documents\Cyberlab\Scripts'

.\Get-AuthEvents.ps1 `
  -DaysBack 7 `
  -EventIds 4624,4625,4740,4768,4771,4772,4776,4777 `
  -OutputPath 'C:\Users\Public\Documents\Cyberlab\DC-Auth-Events.csv'
```

The collector exports fields such as the event time, source computer, event ID, account, logon type, workstation, source IP and status codes. It also accepts a `-MaxEvents` limit. If that limit is reached, the script warns that the export may be incomplete.

To save the effective audit policy from either machine:

```powershell
.\Export-AuditPolicySnapshot.ps1 `
  -OutputPath 'C:\Users\Public\Documents\Cyberlab\AuditPolicySnapshot.txt'
```

Keep the client and domain-controller exports separate during initial analysis. The same authentication activity can create different event records on different machines, so combining both files without checking for duplicates can inflate the counts.

## 3. Run the detection scripts

Copy the exported CSV files into an `output/` directory in the repository root. The directory is ignored by Git.

To look for repeated failed logons against one account:

```powershell
.\scripts\Detect-RepeatedFailedLogons.ps1 `
  -InputPath '.\output\DC-Auth-Events.csv' `
  -OutputPath '.\output\Repeated-Failed-Logon-Alerts.csv' `
  -Threshold 2 `
  -WindowMinutes 5 `
  -EventIds 4625
```

To look for possible password-spray activity from one source IP:

```powershell
.\scripts\Detect-PasswordSpray.ps1 `
  -InputPath '.\output\DC-Auth-Events.csv' `
  -OutputPath '.\output\Password-Spray-Alerts.csv' `
  -AccountThreshold 5 `
  -WindowMinutes 10 `
  -EventIds 4771,4772
```

The repeated-failure rule groups events by account and event ID. It checks the maximum number of failures inside the configured sliding time window, rather than treating every event in a longer cluster as though they all happened within that window.

The password-spray rule groups events by normalised source IP and checks how many distinct accounts appear within the configured time window. IPv4-mapped IPv6 addresses are normalised where .NET can parse them. Events without a usable source IP cannot contribute to this rule.

An alert is a reason to investigate, not proof of an attack or compromised account. Check the event details, source machine, account type, status codes and surrounding activity before deciding what happened.

## 4. Run the synthetic tests

From the repository root:

```powershell
.\tests\Invoke-DetectionTests.ps1
```

The test runner creates synthetic CSV data, runs both detection scripts and compares the results with the expected alert counts. The 17 test cases cover:

- Single failures and repeated failures.
- Events inside, outside and exactly on the configured time-window boundary.
- Separate and overlapping clusters.
- Different accounts and different event IDs.
- Kerberos-related failure scenarios.
- Password-spray thresholds, multiple source IPs and repeated attempts against one account.
- IPv4-mapped IPv6 addresses and events with no source IP.

**Latest test run: 17 passed, 0 failed.** The test summary is saved in `docs/Test-Summary.csv`.

These tests use synthetic input. They check the detection logic; they do not prove that every Windows audit setting, event source or collection path is working in every environment.

## 5. Results from the lab

The event exports from the lab contained the following records:

| Event ID | DC01 | CLIENT01 |
|---|---:|---:|
| 4624 — Successful logon | 3,015 | 1,135 |
| 4625 — Failed logon | 12 | 12 |
| 4768 — Kerberos TGT request | 168 | — |
| 4776 — NTLM credential validation | 10 | — |

Running the repeated-failure detector against the exported 4625 events produced **three alert groups on DC01** and **four on CLIENT01**. The separate Kerberos, NTLM and password-spray runs did not produce alerts at the configured thresholds.

Some of the repeated-failure records correspond to controlled lab activity. The other records should still be checked against the event details and lab notes; a detector cannot determine intent on its own. These counts describe the exports used for this run and will change as new events are generated or older events are overwritten by log retention.

## Event ID reference

| Event ID | Meaning | Where it is useful |
|---|---|---|
| 4624 | Successful logon | Investigating successful logons; check the logon type. |
| 4625 | Failed logon | Investigating failed logons on the computer that recorded the event. |
| 4740 | User account locked out | Investigating account lockouts. |
| 4768 | Kerberos ticket-granting ticket (TGT) requested | Reviewing Kerberos authentication service activity and status. |
| 4771 | Kerberos pre-authentication failed | Investigating failed Kerberos pre-authentication on a domain controller. |
| 4772 | Kerberos TGT request failed | Reviewing failed Kerberos ticket requests. |
| 4776 | NTLM credential validation | Reviewing credential validation by the authority for the account. |
| 4777 | Domain controller failed to validate credentials | Investigating failed NTLM credential validation. |

The fields available in an event depend on its version and the Windows configuration. Refer to Microsoft's event documentation when interpreting individual records.

## Limitations

- This is a small PowerShell lab, not a production SIEM.
- Collection is run locally on each machine; there is no continuous or centralised event forwarding.
- The detection scripts analyse CSV exports rather than monitoring events in real time.
- Some event types do not provide a source IP, which limits IP-based detection.
- NAT, proxies, shared machines and service accounts can affect password-spray results.
- Audit policy and Security log retention affect which events are available.
- The scripts identify patterns for review. They do not establish intent, prove compromise or automatically disable accounts.

A production implementation would need centralised collection, duplicate handling, time synchronisation, access controls, alert prioritisation and monitoring of collection health.

## References

- [Microsoft: Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft: Event 4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776)
- [Microsoft: Active Directory events to monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [GitHub: About push protection](https://docs.github.com/en/code-security/how-tos/secure-your-secrets/prevent-future-leaks/enable-push-protection)

---

**Maintainer:** [PharreII](https://github.com/PharreII)
