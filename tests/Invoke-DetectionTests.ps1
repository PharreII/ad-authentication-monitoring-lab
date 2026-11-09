[CmdletBinding()]
param(
    [string]$ResultsDirectory = (Join-Path $PSScriptRoot 'results')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$repeatedDetector = Join-Path $projectRoot 'scripts\Detect-RepeatedFailedLogons.ps1'
$sprayDetector = Join-Path $projectRoot 'scripts\Detect-PasswordSpray.ps1'

foreach ($path in @($repeatedDetector, $sprayDetector)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required detector not found: $path"
    }
}

if (-not (Test-Path -LiteralPath $ResultsDirectory)) {
    New-Item -Path $ResultsDirectory -ItemType Directory -Force | Out-Null
}

$script:TestBaseTime = [datetimeoffset]::new(2026, 11, 8, 12, 0, 0, [timespan]::Zero)

function New-TestEvent {
    param(
        [Parameter(Mandatory)][int]$OffsetSeconds,
        [Parameter(Mandatory)][string]$Account,
        [string]$SourceIP = '192.168.183.130',
        [string]$EventID = '4625'
    )

    return [pscustomobject]@{
        TimeCreated = $script:TestBaseTime.AddSeconds($OffsetSeconds).ToString('o')
        Computer    = 'CLIENT01.lab.local'
        EventID     = $EventID
        Result      = 'Failure'
        Account     = $Account
        Domain      = 'LAB.LOCAL'
        LogonType   = '3'
        Workstation = 'CLIENT01'
        SourceIP    = $SourceIP
        Status      = '0xc000006d'
        SubStatus   = '0xc000006a'
    }
}

$tests = New-Object System.Collections.Generic.List[object]

# Repeated failed-logon tests
$tests.Add([pscustomobject]@{ Name='Repeated - single failure'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user')); ExpectedAlerts=0; ValueColumn='PeakCount'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Repeated - two failures inside five minutes'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 22 'LAB\lab.user')); ExpectedAlerts=1; ValueColumn='PeakCount'; ExpectedValues=@(2) })
$tests.Add([pscustomobject]@{ Name='Repeated - two failures outside five minutes'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 360 'LAB\lab.user')); ExpectedAlerts=0; ValueColumn='PeakCount'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Repeated - three failures inside one window'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 22 'LAB\lab.user'),(New-TestEvent 80 'LAB\lab.user')); ExpectedAlerts=1; ValueColumn='PeakCount'; ExpectedValues=@(3) })
$tests.Add([pscustomobject]@{ Name='Repeated - two separate clusters'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 30 'LAB\lab.user'),(New-TestEvent 600 'LAB\lab.user'),(New-TestEvent 630 'LAB\lab.user')); ExpectedAlerts=2; ValueColumn='PeakCount'; ExpectedValues=@(2,2) })
$tests.Add([pscustomobject]@{ Name='Repeated - different accounts are not combined'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 20 'LAB\other.user')); ExpectedAlerts=0; ValueColumn='PeakCount'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Repeated - exact five-minute boundary'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 300 'LAB\lab.user')); ExpectedAlerts=1; ValueColumn='PeakCount'; ExpectedValues=@(2) })
$tests.Add([pscustomobject]@{ Name='Repeated - overlapping qualifying windows'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 240 'LAB\lab.user'),(New-TestEvent 480 'LAB\lab.user')); ExpectedAlerts=1; ValueColumn='PeakCount'; ExpectedValues=@(2) })
$tests.Add([pscustomobject]@{ Name='Repeated - two Kerberos failures trigger'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user' '192.168.183.130' '4771'),(New-TestEvent 30 'LAB\lab.user' '192.168.183.130' '4771')); ExpectedAlerts=1; ValueColumn='PeakCount'; ExpectedValues=@(2) })
$tests.Add([pscustomobject]@{ Name='Repeated - different event IDs are not combined'; Detector='Repeated'; Events=@((New-TestEvent 0 'LAB\lab.user' '192.168.183.130' '4625'),(New-TestEvent 30 'LAB\lab.user' '192.168.183.130' '4776')); ExpectedAlerts=0; ValueColumn='PeakCount'; ExpectedValues=@() })

# Password-spray tests
$tests.Add([pscustomobject]@{ Name='Spray - five accounts from one IP'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\user01'),(New-TestEvent 20 'LAB\user02'),(New-TestEvent 40 'LAB\user03'),(New-TestEvent 60 'LAB\user04'),(New-TestEvent 80 'LAB\user05')); ExpectedAlerts=1; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@(5) })
$tests.Add([pscustomobject]@{ Name='Spray - four accounts below threshold'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\user01'),(New-TestEvent 20 'LAB\user02'),(New-TestEvent 40 'LAB\user03'),(New-TestEvent 60 'LAB\user04')); ExpectedAlerts=0; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Spray - accounts split across two IPs'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\user01' '192.168.183.130'),(New-TestEvent 10 'LAB\user02' '192.168.183.130'),(New-TestEvent 20 'LAB\user03' '192.168.183.130'),(New-TestEvent 30 'LAB\user04' '192.168.183.131'),(New-TestEvent 40 'LAB\user05' '192.168.183.131')); ExpectedAlerts=0; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Spray - repeated failures against one account'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\lab.user'),(New-TestEvent 20 'LAB\lab.user'),(New-TestEvent 40 'LAB\lab.user'),(New-TestEvent 60 'LAB\lab.user'),(New-TestEvent 80 'LAB\lab.user')); ExpectedAlerts=0; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Spray - IPv4-mapped IPv6 address normalisation'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\user01' '::ffff:192.168.183.130'),(New-TestEvent 20 'LAB\user02' '192.168.183.130'),(New-TestEvent 40 'LAB\user03' '::ffff:192.168.183.130'),(New-TestEvent 60 'LAB\user04' '192.168.183.130'),(New-TestEvent 80 'LAB\user05' '::ffff:192.168.183.130')); ExpectedAlerts=1; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@(5) })
$tests.Add([pscustomobject]@{ Name='Spray - accounts outside ten-minute window'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\user01'),(New-TestEvent 180 'LAB\user02'),(New-TestEvent 360 'LAB\user03'),(New-TestEvent 540 'LAB\user04'),(New-TestEvent 660 'LAB\user05')); ExpectedAlerts=0; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@() })
$tests.Add([pscustomobject]@{ Name='Spray - no source IP is not counted'; Detector='Spray'; Events=@((New-TestEvent 0 'LAB\user01' ''),(New-TestEvent 20 'LAB\user02' ''),(New-TestEvent 40 'LAB\user03' ''),(New-TestEvent 60 'LAB\user04' ''),(New-TestEvent 80 'LAB\user05' '')); ExpectedAlerts=0; ValueColumn='PeakDistinctAccounts'; ExpectedValues=@() })

$results = New-Object System.Collections.Generic.List[object]
$testNumber = 0

foreach ($test in $tests) {
    $testNumber++
    $safeName = $test.Name -replace '[^A-Za-z0-9-]', '-'
    $inputPath = Join-Path $ResultsDirectory "$safeName-Input.csv"
    $outputPath = Join-Path $ResultsDirectory "$safeName-Alerts.csv"

    $test.Events | Export-Csv -LiteralPath $inputPath -NoTypeInformation -Encoding UTF8
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Force
    }

    $detectorPath = if ($test.Detector -eq 'Repeated') { $repeatedDetector } else { $sprayDetector }
    $arguments = @{
        InputPath  = $inputPath
        OutputPath = $outputPath
    }

    if ($test.Detector -eq 'Repeated') {
        $arguments['Threshold'] = 2
        $arguments['WindowMinutes'] = 5
    }
    else {
        $arguments['AccountThreshold'] = 5
        $arguments['WindowMinutes'] = 10
    }

    Write-Host "`nTEST $testNumber`: $($test.Name)" -ForegroundColor Cyan

    try {
        & $detectorPath @arguments | Out-Null
        if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
            throw 'Detector did not create its output CSV.'
        }

        $actualRows = @(Import-Csv -LiteralPath $outputPath)
        $actualValues = @(
            $actualRows | ForEach-Object {
                $property = $_.PSObject.Properties[$test.ValueColumn]
                if ($null -ne $property) { [int]$property.Value }
            } | Sort-Object
        )
        $expectedValues = @($test.ExpectedValues | Sort-Object)
        $valuesMatch = (($actualValues -join ',') -eq ($expectedValues -join ','))
        $passed = ($actualRows.Count -eq $test.ExpectedAlerts) -and $valuesMatch

        $results.Add([pscustomobject]@{
            Test = $test.Name
            ExpectedAlerts = $test.ExpectedAlerts
            ActualAlerts = $actualRows.Count
            ExpectedValues = $expectedValues -join ','
            ActualValues = $actualValues -join ','
            Result = if ($passed) { 'PASS' } else { 'FAIL' }
        })
    }
    catch {
        $results.Add([pscustomobject]@{
            Test = $test.Name
            ExpectedAlerts = $test.ExpectedAlerts
            ActualAlerts = -1
            ExpectedValues = $test.ExpectedValues -join ','
            ActualValues = ''
            Result = "ERROR: $($_.Exception.Message)"
        })
    }
}

$summaryPath = Join-Path $ResultsDirectory 'Test-Summary.csv'
$results | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8

Write-Host "`n========== COMPLETE TEST SUMMARY ==========" -ForegroundColor Cyan
$results | Format-Table Test, ExpectedAlerts, ActualAlerts, ExpectedValues, ActualValues, Result -AutoSize

$failed = @($results | Where-Object { $_.Result -ne 'PASS' })
Write-Host "`nTests run: $($results.Count)"
Write-Host "Passed: $(@($results | Where-Object { $_.Result -eq 'PASS' }).Count)"
Write-Host "Failed/errors: $($failed.Count)"
Write-Host "Summary: $summaryPath"

if ($failed.Count -gt 0) {
    throw 'One or more detection tests failed. Review the summary before publishing.'
}

Write-Host "ALL $($results.Count) TESTS PASSED" -ForegroundColor Green
