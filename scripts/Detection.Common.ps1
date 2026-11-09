function ConvertTo-NormalizedSourceIP {
    param([AllowNull()][string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address) -or $Address -eq '-') {
        return ''
    }

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($Address, [ref]$parsedAddress)) {
        if ($parsedAddress.IsIPv4MappedToIPv6) {
            return $parsedAddress.MapToIPv4().ToString()
        }
        return $parsedAddress.ToString()
    }

    return $Address.Trim()
}

function Get-FailedAuthenticationEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [int[]]$EventIds = @(4625, 4768, 4771, 4772, 4776, 4777)
    )

    if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
        throw "Input CSV not found: $InputPath"
    }

    $rows = @(Import-Csv -LiteralPath $InputPath)
    if ($rows.Count -eq 0) {
        return @()
    }

    $requiredColumns = @('TimeCreated', 'EventID', 'Result', 'Account')
    $availableColumns = @($rows[0].PSObject.Properties.Name)
    $missingColumns = @($requiredColumns | Where-Object { $availableColumns -notcontains $_ })
    if ($missingColumns.Count -gt 0) {
        throw "Input CSV is missing required columns: $($missingColumns -join ', ')"
    }

    $supportedFailureIds = @('4625', '4768', '4771', '4772', '4776', '4777')
    $selectedFailureIds = @($EventIds | ForEach-Object { [string]$_ })
    $unsupportedIds = @($selectedFailureIds | Where-Object { $supportedFailureIds -notcontains $_ })
    if ($unsupportedIds.Count -gt 0) {
        throw "Unsupported failure Event ID(s): $($unsupportedIds -join ', ')"
    }
    $parsedEvents = New-Object System.Collections.Generic.List[object]

    foreach ($row in $rows) {
        if ([string]$row.Result -ine 'Failure') { continue }
        if ($supportedFailureIds -notcontains ([string]$row.EventID)) { continue }
        if ($selectedFailureIds -notcontains ([string]$row.EventID)) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$row.Account)) { continue }

        $timestamp = [datetimeoffset]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeLocal
        $parsed = [datetimeoffset]::TryParse(
            [string]$row.TimeCreated,
            [System.Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$timestamp
        )

        if (-not $parsed) {
            $parsed = [datetimeoffset]::TryParse(
                [string]$row.TimeCreated,
                [System.Globalization.CultureInfo]::CurrentCulture,
                $styles,
                [ref]$timestamp
            )
        }

        if (-not $parsed) {
            Write-Warning "Skipping row with an unreadable timestamp: $($row.TimeCreated)"
            continue
        }

        $sourceIP = [string]$row.SourceIP
        $parsedEvents.Add([pscustomobject]@{
            Timestamp          = $timestamp
            Account            = ([string]$row.Account).Trim()
            EventID            = [string]$row.EventID
            SourceIP           = $sourceIP
            NormalizedSourceIP = ConvertTo-NormalizedSourceIP -Address $sourceIP
            Computer           = [string]$row.Computer
            Workstation        = [string]$row.Workstation
            Status             = [string]$row.Status
        })
    }

    return $parsedEvents.ToArray()
}

function Get-ConnectedEventClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Events,
        [Parameter(Mandatory)][ValidateRange(1, 1440)][int]$WindowMinutes
    )

    $ordered = @($Events | Sort-Object -Property Timestamp)
    $clusters = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[object]
    $previous = $null

    foreach ($event in $ordered) {
        if ($null -ne $previous) {
            $gapSeconds = ($event.Timestamp - $previous.Timestamp).TotalSeconds
            if ($gapSeconds -gt ($WindowMinutes * 60)) {
                $clusters.Add([pscustomobject]@{ Events = @($current.ToArray()) })
                $current.Clear()
            }
        }

        $current.Add($event)
        $previous = $event
    }

    if ($current.Count -gt 0) {
        $clusters.Add([pscustomobject]@{ Events = @($current.ToArray()) })
    }

    return $clusters.ToArray()
}

function Get-PeakFailureWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Events,
        [Parameter(Mandatory)][ValidateRange(1, 1440)][int]$WindowMinutes
    )

    $ordered = @($Events | Sort-Object -Property Timestamp)
    $left = 0
    $peakCount = 0
    $bestStart = 0
    $bestEnd = 0

    for ($right = 0; $right -lt $ordered.Count; $right++) {
        while (
            ($left -le $right) -and
            (($ordered[$right].Timestamp - $ordered[$left].Timestamp).TotalSeconds -gt ($WindowMinutes * 60))
        ) {
            $left++
        }

        $count = $right - $left + 1
        if ($count -gt $peakCount) {
            $peakCount = $count
            $bestStart = $left
            $bestEnd = $right
        }
    }

    $peakEvents = @($ordered[$bestStart..$bestEnd])
    return [pscustomobject]@{
        PeakCount = $peakCount
        PeakEvents = $peakEvents
        WindowStart = $ordered[$bestStart].Timestamp
        WindowEnd = $ordered[$bestEnd].Timestamp
        ClusterStart = $ordered[0].Timestamp
        ClusterEnd = $ordered[$ordered.Count - 1].Timestamp
        EventCount = $ordered.Count
    }
}

function Write-DetectionCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string[]]$Columns
    )

    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $outputDirectory = Split-Path -Parent $resolvedOutput
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -LiteralPath $resolvedOutput -NoTypeInformation -Encoding UTF8
    }
    else {
        $header = ($Columns | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ','
        Set-Content -LiteralPath $resolvedOutput -Value $header -Encoding UTF8
    }

    return $resolvedOutput
}
