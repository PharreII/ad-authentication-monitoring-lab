[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\output\AuditPolicySnapshot.txt')
)

$ErrorActionPreference = 'Stop'
$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$directory = Split-Path -Parent $resolvedOutput
if (-not (Test-Path -LiteralPath $directory)) {
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

$lines = @(
    "Computer: $env:COMPUTERNAME"
    "Captured: $(Get-Date -Format o)"
    ''
    '=== Advanced audit policy ==='
)

$auditOutput = & auditpol.exe /get /category:*
if ($LASTEXITCODE -ne 0) {
    throw 'auditpol.exe returned an error. Run this script elevated.'
}
$lines += $auditOutput
$lines += ''
$lines += '=== Security log status ==='
$securityLog = Get-WinEvent -ListLog Security
$lines += "IsEnabled: $($securityLog.IsEnabled)"
$lines += "RecordCount: $($securityLog.RecordCount)"
$lines += "MaximumSizeInBytes: $($securityLog.MaximumSizeInBytes)"
$lines += "LogMode: $($securityLog.LogMode)"

Set-Content -LiteralPath $resolvedOutput -Value $lines -Encoding UTF8
Write-Host "Audit policy snapshot saved to: $resolvedOutput" -ForegroundColor Green
