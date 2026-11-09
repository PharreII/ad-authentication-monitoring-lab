# Operator Runbook

## Before collecting

1. Confirm DC01 and CLIENT01 are powered on and the domain is healthy.
2. Confirm both machines have correct time and time zone.
3. Verify effective audit policy with `auditpol /get /category:*`.
4. Confirm the Security log is enabled and retention is adequate.
5. Run PowerShell elevated when reading the Security log.

## Collect on CLIENT01

```powershell
.\Get-AuthEvents.ps1 -DaysBack 7 -EventIds 4624,4625 -OutputPath 'C:\Users\Public\Documents\Cyberlab\Client-Auth-Events.csv'
```

## Collect on DC01

```powershell
.\Get-AuthEvents.ps1 -DaysBack 7 -EventIds 4624,4625,4740,4768,4771,4772,4776,4777 -OutputPath 'C:\Users\Public\Documents\Cyberlab\DC-Auth-Events.csv'
```

## Run analysis on the host

```powershell
.\scripts\Detect-RepeatedFailedLogons.ps1 -InputPath '.\output\DC-Auth-Events.csv' -OutputPath '.\output\DC-Repeated-Failures.csv' -Threshold 2 -WindowMinutes 5 -EventIds 4625

.\scripts\Detect-PasswordSpray.ps1 -InputPath '.\output\DC-Auth-Events.csv' -OutputPath '.\output\DC-Password-Spray.csv' -AccountThreshold 5 -WindowMinutes 10 -EventIds 4771,4772
```

Run the repeated-failure detector separately against `Client-Auth-Events.csv` if you want endpoint-only results. Do not concatenate the endpoint and DC reports without a documented deduplication strategy.

## Validate the scripts

```powershell
.\tests\Invoke-DetectionTests.ps1
```

The test runner creates synthetic files only in `tests\results`. Review its final summary and investigate any test failures before publishing.
