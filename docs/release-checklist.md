# GitHub Release Checklist

## Technical verification

- [ ] Run `Get-AuthEvents.ps1` on CLIENT01 and review the CSV.
- [ ] Run `Get-AuthEvents.ps1` on DC01 and review the CSV.
- [ ] Export and retain audit-policy snapshots from both machines.
- [ ] Verify the audit subcategories relevant to each event type.
- [ ] Run the repeated-failed-logon detector on a real lab export.
- [ ] Run the password-spray detector on a synthetic test fixture.
- [ ] Run `tests/Invoke-DetectionTests.ps1` and record the actual result.
- [ ] Review false positives, missing IPs, time zones and event retention.
- [ ] Confirm test scripts do not alter accounts, audit policies or domain configuration.

## Documentation and evidence

- [ ] Update the README with actual VM names, sanitised network details and versions.
- [ ] Update architecture diagram if implementation differs.
- [ ] Add a sanitised investigation record.
- [ ] Add a synthetic test summary, clearly labelled as synthetic.
- [ ] Add screenshots with passwords, personal usernames and sensitive details removed.
- [ ] State limitations and avoid claims of production readiness.

## Security review

- [ ] No passwords, tokens, keys or secrets.
- [ ] No raw `.evtx`, `.etl`, packet captures or VM disks.
- [ ] No real user event exports or identifiable usernames.
- [ ] No personal Windows paths or usernames in published files.
- [ ] Review staged files using `git status` and `git diff --cached`.

## Publish

- [ ] Add a licence if you want others to reuse the code.
- [ ] Initialise Git and commit reviewed files.
- [ ] Create the GitHub repository.
- [ ] Push to `main`.
- [ ] Enable secret scanning / push protection where available.
- [ ] Open the public README and verify screenshots and links render correctly.
