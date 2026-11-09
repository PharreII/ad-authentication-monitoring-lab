[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot '..\output\Auth-Events.csv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\output\Password-Spray-Alerts.csv'),
    [ValidateRange(2, 1000)][int]$AccountThreshold = 5,
    [ValidateRange(1, 1440)][int]$WindowMinutes = 10,
    [int[]]$EventIds = @(4625, 4768, 4771, 4772, 4776, 4777)
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Detection.Common.ps1')

$failedEvents = @(Get-FailedAuthenticationEvents -InputPath $InputPath -EventIds $EventIds)
$networkFailures = @(
    $failedEvents | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.NormalizedSourceIP)
    }
)

$alerts = New-Object System.Collections.Generic.List[object]

foreach ($ipGroup in ($networkFailures | Group-Object -Property NormalizedSourceIP)) {
    $clusters = @(Get-ConnectedEventClusters -Events @($ipGroup.Group) -WindowMinutes $WindowMinutes)

    foreach ($cluster in $clusters) {
        $clusterEvents = @($cluster.Events | Sort-Object Timestamp)
        if ($clusterEvents.Count -eq 0) { continue }

        $left = 0
        $peakDistinctCount = 0
        $bestStart = 0
        $bestEnd = 0
        $bestAccounts = @()

        for ($right = 0; $right -lt $clusterEvents.Count; $right++) {
            while (
                ($left -le $right) -and
                (($clusterEvents[$right].Timestamp - $clusterEvents[$left].Timestamp).TotalSeconds -gt ($WindowMinutes * 60))
            ) {
                $left++
            }

            $windowEvents = @($clusterEvents[$left..$right])
            $distinctAccounts = @(
                $windowEvents |
                    ForEach-Object { $_.Account } |
                    Sort-Object -Unique
            )

            if ($distinctAccounts.Count -gt $peakDistinctCount) {
                $peakDistinctCount = $distinctAccounts.Count
                $bestStart = $left
                $bestEnd = $right
                $bestAccounts = $distinctAccounts
            }
        }

        if ($peakDistinctCount -lt $AccountThreshold) { continue }

        $peakEvents = @($clusterEvents[$bestStart..$bestEnd])
        $totalDistinctAccounts = @($clusterEvents | ForEach-Object { $_.Account } | Sort-Object -Unique).Count
        $evidence = @(
            $peakEvents | ForEach-Object {
                '{0} [Account={1}; EventID={2}]' -f $_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss zzz'), $_.Account, $_.EventID
            }
        ) -join ' | '

        $alerts.Add([pscustomobject]@{
            Detection                 = 'Potential password spray'
            SourceIP                  = $ipGroup.Name
            EventCount                = $clusterEvents.Count
            DistinctAccountsInCluster = $totalDistinctAccounts
            PeakDistinctAccounts     = $peakDistinctCount
            AccountThreshold         = $AccountThreshold
            WindowMinutes            = $WindowMinutes
            AccountsInTriggerWindow  = ($bestAccounts -join '; ')
            ClusterStart             = $clusterEvents[0].Timestamp.ToString('o')
            ClusterEnd               = $clusterEvents[$clusterEvents.Count - 1].Timestamp.ToString('o')
            TriggerWindowStart       = $clusterEvents[$bestStart].Timestamp.ToString('o')
            TriggerWindowEnd         = $clusterEvents[$bestEnd].Timestamp.ToString('o')
            Evidence                 = $evidence
        })
    }
}

$columns = @(
    'Detection', 'SourceIP', 'EventCount', 'DistinctAccountsInCluster',
    'PeakDistinctAccounts', 'AccountThreshold', 'WindowMinutes',
    'AccountsInTriggerWindow', 'ClusterStart', 'ClusterEnd',
    'TriggerWindowStart', 'TriggerWindowEnd', 'Evidence'
)

$writtenPath = Write-DetectionCsv -Rows @($alerts.ToArray()) -OutputPath $OutputPath -Columns $columns

if ($alerts.Count -gt 0) {
    Write-Host "`nPOTENTIAL PASSWORD-SPRAY PATTERN DETECTED" -ForegroundColor Red
    $alerts | Format-Table SourceIP, EventCount, PeakDistinctAccounts, AccountsInTriggerWindow, TriggerWindowStart, TriggerWindowEnd -AutoSize
}
else {
    Write-Host "`nNo password-spray pattern detected." -ForegroundColor Green
    Write-Host 'This does not prove that all activity was benign.'
}

Write-Host "Failed-authentication events with source IP analysed: $($networkFailures.Count)"
Write-Host "Alert count: $($alerts.Count)"
Write-Host "Alerts saved to: $writtenPath"
