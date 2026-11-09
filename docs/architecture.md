# Architecture and Lab Inventory

## Purpose

This document records the lab components and the direction of authentication telemetry. Update it to match the final implementation rather than treating example addresses as authoritative.

## Components

| Component | Role | Operating system | Example address |
|---|---|---|---|
| DC01 | Active Directory Domain Services, DNS, Kerberos KDC and Group Policy | Windows Server 2025 | `192.168.183.10` |
| CLIENT01 | Domain-joined workstation and source of endpoint logon events | Windows 11 Enterprise Evaluation | `192.168.183.130` |
| Host | VMware Workstation, script development, evidence and Git | Windows | Host network configuration not published |

Domain: `lab.local`
Virtual network: VMware VMnet8 NAT (`192.168.183.0/24` in the example lab).

## Data flow

1. A user or test process authenticates from CLIENT01.
2. Windows records local logon events in the CLIENT01 Security log.
3. Domain authentication may generate corresponding authentication-service events on DC01, depending on the protocol and audit configuration.
4. `Get-AuthEvents.ps1` is run locally on each VM to export selected Security events.
5. The exports are transferred to the analysis host and remain separated by source computer.
6. Detection scripts analyse one source report at a time and export CSV alerts.
7. Synthetic tests exercise expected behaviours without generating real authentication failures.

## Time and correlation

Record each machine's time zone and UTC time when collecting evidence. Use the event's XML/SystemTime or ISO-8601 timestamp where possible. Do not correlate records solely because displayed local times are close. Confirm account, source machine, source address, event ID and authentication protocol where available.

## Safety boundaries

All authentication tests must use dedicated lab test accounts and the user's own isolated VM network. Do not use production accounts or external systems. Do not publish raw event logs or VM disks.
