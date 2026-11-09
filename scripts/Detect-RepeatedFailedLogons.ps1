[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot '..\output\Auth-Events.csv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\output\Repeated-Failed-Logon-Alerts.csv'),
    [ValidateRange(2, 100)][int]$Threshold = 2,
    [ValidateRange(1, 1440)][int]$WindowMinutes = 5,
    [int[]]$EventIds = @(4625, 4768, 4771, 4772, 4776, 4777)
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Detection.Common.ps1')

$failedEvents = @(Get-FailedAuthenticationEvents -InputPath $InputPath -EventIds $EventIds)
$alerts = New-Object System.Collections.Generic.List[object]

foreach ($accountEventGroup in ($failedEvents | Group-Object -Property Account, EventID)) {
    $groupEvents = @($accountEventGroup.Group)
    $account = $groupEvents[0].Account
    $eventId = $groupEvents[0].EventID
    $clusters = @(Get-ConnectedEventClusters -Events $groupEvents -WindowMinutes $WindowMinutes)

    foreach ($cluster in $clusters) {
        $clusterEvents = @($cluster.Events)
        if ($clusterEvents.Count -eq 0) { continue }

        $peak = Get-PeakFailureWindow -Events $clusterEvents -WindowMinutes $WindowMinutes
        if ($peak.PeakCount -lt $Threshold) { continue }

        $sourceIPs = @(
            $clusterEvents |
                ForEach-Object { $_.NormalizedSourceIP } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique
        )
        if ($sourceIPs.Count -eq 0) { $sourceIPText = 'Not available' }
        else { $sourceIPText = $sourceIPs -join '; ' }

        $evidence = @(
            $peak.PeakEvents | ForEach-Object {
                '{0} [EventID={1}; SourceIP={2}]' -f $_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss zzz'), $_.EventID, $(if ($_.NormalizedSourceIP) { $_.NormalizedSourceIP } else { 'Not available' })
            }
        ) -join ' | '

        $alerts.Add([pscustomobject]@{
            Detection         = 'Repeated failed logons'
            Account           = $account
            EventID            = $eventId
            EventCount        = $peak.EventCount
            PeakCount         = $peak.PeakCount
            WindowMinutes     = $WindowMinutes
            Threshold         = $Threshold
            SourceIPs         = $sourceIPText
            ClusterStart      = $peak.ClusterStart.ToString('o')
            ClusterEnd        = $peak.ClusterEnd.ToString('o')
            TriggerWindowStart = $peak.WindowStart.ToString('o')
            TriggerWindowEnd   = $peak.WindowEnd.ToString('o')
            Evidence           = $evidence
        })
    }
}

$columns = @(
    'Detection', 'Account', 'EventID', 'EventCount', 'PeakCount', 'WindowMinutes',
    'Threshold', 'SourceIPs', 'ClusterStart', 'ClusterEnd',
    'TriggerWindowStart', 'TriggerWindowEnd', 'Evidence'
)

$writtenPath = Write-DetectionCsv -Rows @($alerts.ToArray()) -OutputPath $OutputPath -Columns $columns

if ($alerts.Count -gt 0) {
    Write-Host "`nDETECTION TRIGGERED" -ForegroundColor Red
    $alerts | Format-Table Detection, Account, EventID, EventCount, PeakCount, SourceIPs, TriggerWindowStart, TriggerWindowEnd -AutoSize
}
else {
    Write-Host "`nNo repeated-failure pattern detected." -ForegroundColor Green
    Write-Host 'This does not prove that all activity was benign.'
}

Write-Host "Failed-authentication events analysed: $($failedEvents.Count)"
Write-Host "Alert count: $($alerts.Count)"
Write-Host "Alerts saved to: $writtenPath"
