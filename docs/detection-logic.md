# Detection Logic and Tuning

## Rule 1 — Repeated failed logons against one account

**Default threshold:** 2 failed authentication events.
**Default window:** 5 minutes.
**Grouping key:** account and event ID.

Input events are restricted to rows with `Result=Failure` and event IDs 4625, 4768, 4771, 4772, 4776 or 4777. The detector groups events by account and event ID, preventing distinct Windows audit event types from being automatically counted as separate attempts. It forms connected clusters where the gap between consecutive events does not exceed the configured window. It then calculates the maximum event count in any sliding window within each cluster. An alert is emitted when that peak reaches the threshold.

This approach allows a cluster to contain multiple overlapping qualifying windows while reporting the exact trigger window separately from the wider cluster boundaries.

### Investigate

- Was the account expected to be used at that time?
- Is the source IP or workstation known?
- Are events local interactive failures (for example, 4625 Logon Type 2) or network/authentication-service failures?
- What do Status and SubStatus indicate?
- Did a successful authentication occur afterwards?
- Are there account lockout events (4740)?

## Rule 2 — Potential password spray

**Default threshold:** 5 distinct accounts.
**Default window:** 10 minutes.
**Grouping key:** normalised source IP.

The detector requires failed authentication rows with a parseable source IP. It groups events by source address and checks the maximum number of distinct account names in any sliding time window. Repeated failures against one account do not increase the distinct-account count.

IPv4-mapped IPv6 addresses such as `::ffff:192.0.2.10` are converted to the IPv4 representation where supported.

### Investigate

- Does the source IP belong to a workstation, NAT gateway, VPN or approved scanner?
- Are the targeted accounts valid, disabled, stale or privileged?
- Are the failures distributed over several services or protocols?
- Were there successful logons from the same source?
- Are there lockouts or follow-on activity?

## Limitations and tuning

Thresholds are illustrative starting points for a small lab. They are not universal indicators of attack. In production, tune per environment, identity type, authentication protocol and source topology. Consider service accounts, shared egress NAT, vulnerability scanners, scheduled jobs and misconfigured applications.

The detector does not block, disable or lock accounts. It generates reviewable CSV alerts only.
