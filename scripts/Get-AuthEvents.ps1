[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [int[]]$EventIds = @(4624, 4625, 4740, 4768, 4771, 4772, 4776, 4777),

    [string]$AccountName,

    [ValidateRange(100, 200000)]
    [int]$MaxEvents = 20000,

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\output\Auth-Events.csv')
)

$ErrorActionPreference = 'Stop'

$columns = @(
    'TimeCreated', 'Computer', 'EventRecordId', 'EventID', 'Result',
    'Account', 'Domain', 'LogonType', 'Workstation', 'SourceIP',
    'Status', 'SubStatus', 'AuthenticationPackage', 'LogonProcess',
    'PreAuthType', 'ServiceName', 'FailureReason', 'CallerComputerName',
    'EventDataJson'
)

function Get-FirstNonEmptyValue {
    param(
        [hashtable]$Data,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Data.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$name])) {
            return [string]$Data[$name]
        }
    }

    return ''
}

$startTime = (Get-Date).AddDays(-$DaysBack)
$filter = @{
    LogName   = 'Security'
    StartTime = $startTime
    Id        = $EventIds
}

Write-Host "Reading Security events on $env:COMPUTERNAME from $startTime ..." -ForegroundColor Cyan
Write-Host "Event IDs: $($EventIds -join ', ')"

try {
    $eventRecords = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        $eventRecords = @()
    }
    else {
        throw "Unable to read the Security log. Run PowerShell elevated and check Event Log permissions. Details: $($_.Exception.Message)"
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($event in $eventRecords) {
    [xml]$eventXml = $event.ToXml()
    $data = @{}

    if ($null -ne $eventXml.Event.EventData -and $null -ne $eventXml.Event.EventData.Data) {
        foreach ($item in $eventXml.Event.EventData.Data) {
            $fieldName = [string]$item.Name
            if (-not [string]::IsNullOrWhiteSpace($fieldName)) {
                $data[$fieldName] = [string]$item.'#text'
            }
        }
    }

    $account = Get-FirstNonEmptyValue -Data $data -Names @('TargetUserName', 'AccountName', 'SubjectUserName')
    $domain = Get-FirstNonEmptyValue -Data $data -Names @('TargetDomainName', 'AccountDomain', 'SubjectDomainName')
    $workstation = Get-FirstNonEmptyValue -Data $data -Names @('WorkstationName', 'Workstation', 'CallerComputerName', 'SourceWorkstation')
    $sourceIP = Get-FirstNonEmptyValue -Data $data -Names @('IpAddress', 'ClientAddress', 'SourceAddress')
    $status = Get-FirstNonEmptyValue -Data $data -Names @('Status', 'FailureCode', 'ErrorCode')
    $subStatus = Get-FirstNonEmptyValue -Data $data -Names @('SubStatus')

    if (-not [string]::IsNullOrWhiteSpace($AccountName)) {
        $qualifiedAccount = if ($domain) { "$domain\$account" } else { $account }
        if (($account -ine $AccountName) -and ($qualifiedAccount -ine $AccountName)) {
            continue
        }
    }

    $result = 'Unknown'
    switch ([int]$event.Id) {
        4624 { $result = 'Success' }
        4625 { $result = 'Failure' }
        4771 { $result = 'Failure' }
        4772 { $result = 'Failure' }
        4777 { $result = 'Failure' }
        4740 { $result = 'AccountLockedOut' }
        4768 {
            if ($status -match '^(0x0|0+)$') {
                $result = 'Success'
            }
            elseif (-not [string]::IsNullOrWhiteSpace($status)) {
                $result = 'Failure'
            }
        }
        4776 {
            if ($status -match '^(0x0|0+)$') {
                $result = 'Success'
            }
            elseif (-not [string]::IsNullOrWhiteSpace($status)) {
                $result = 'Failure'
            }
        }
    }

    $eventDataJson = ConvertTo-Json -InputObject $data -Compress -Depth 5

    $results.Add([pscustomobject]@{
        TimeCreated          = $event.TimeCreated.ToString('o')
        Computer             = [string]$event.MachineName
        EventRecordId        = [long]$event.RecordId
        EventID              = [int]$event.Id
        Result               = $result
        Account              = $account
        Domain               = $domain
        LogonType            = (Get-FirstNonEmptyValue -Data $data -Names @('LogonType'))
        Workstation          = $workstation
        SourceIP             = $sourceIP
        Status               = $status
        SubStatus            = $subStatus
        AuthenticationPackage = (Get-FirstNonEmptyValue -Data $data -Names @('AuthenticationPackageName', 'PackageName'))
        LogonProcess         = (Get-FirstNonEmptyValue -Data $data -Names @('LogonProcessName'))
        PreAuthType          = (Get-FirstNonEmptyValue -Data $data -Names @('PreAuthType'))
        ServiceName          = (Get-FirstNonEmptyValue -Data $data -Names @('ServiceName'))
        FailureReason        = (Get-FirstNonEmptyValue -Data $data -Names @('FailureReason'))
        CallerComputerName   = (Get-FirstNonEmptyValue -Data $data -Names @('CallerComputerName'))
        EventDataJson        = $eventDataJson
    })
}

$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutput
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

if ($results.Count -gt 0) {
    $results | Export-Csv -LiteralPath $resolvedOutput -NoTypeInformation -Encoding UTF8
}
else {
    $header = ($columns | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ','
    Set-Content -LiteralPath $resolvedOutput -Value $header -Encoding UTF8
}

Write-Host "Events returned by Windows: $($eventRecords.Count)"
Write-Host "Rows written: $($results.Count)"
if ($eventRecords.Count -ge $MaxEvents) {
    Write-Warning "The -MaxEvents limit ($MaxEvents) was reached. The report may be truncated; rerun with a larger limit or a shorter time range."
}
Write-Host "Output: $resolvedOutput" -ForegroundColor Green
