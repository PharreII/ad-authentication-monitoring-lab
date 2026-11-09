### Day 3 — Windows Security Log Investigation

#### Objective
Investigate a controlled failed logon attempt on a domain-joined Windows workstation and determine what can be established from the Windows Security log.

#### Procedure
- Started the Windows Server domain controller and the Windows 11 client.
- Generated one deliberate failed sign-in attempt using the `LAB\lab.user` account.
- Opened Event Viewer on CLIENT01 and filtered the Security log for Event ID 4625.
- Examined the event's authentication, account, workstation and network fields.

#### Evidence
- **Event ID:** 4625 — An account failed to log on.
- **Computer:** CLIENT01.lab.local.
- **Target account:** `LAB\lab.user`.
- **Logon type:** 2 — Interactive.
- **Status code:** `0xC000006D` — General logon failure.
- **Substatus code:** `0xC000006A` — Incorrect password.
- **Workstation:** CLIENT01.
- **Source address:** `127.0.0.1`.
- **Reported process:** `C:\Windows\System32\svchost.exe`.

#### Findings
The Security log recorded the deliberately generated failed sign-in. The substatus code indicates that the password was incorrect, while logon type 2 identifies an interactive logon attempt.

The event was recorded on CLIENT01, which is consistent with investigating a logon attempt made at that workstation. The loopback address `127.0.0.1` is not evidence that an external system initiated the attempt.

The Subject account was `CLIENT01$`, whereas the account for which the logon failed was `LAB\lab.user`. These fields refer to different aspects of the authentication request.

This exercise demonstrated how Windows Security logs can be used to investigate an authentication failure and identify the account, failure reason and relevant context.

#### Timestamp note
Event Viewer displayed 19 October 2026 at 08:39:10. The event XML recorded 15:39:10 UTC. The workstation's configured time zone should be checked before using these timestamps to correlate events across multiple systems.

#### Conclusion
The investigation successfully identified and interpreted a controlled failed logon using Windows Security Event ID 4625. The next stage is to compare this evidence with a successful logon and investigate how repeated failures could be identified during security monitoring.