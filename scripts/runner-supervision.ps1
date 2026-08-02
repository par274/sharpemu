# Copyright (C) 2026 SharpEmu Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# The controlled runner uses this small state model to keep the launcher and
# the actual emulation process independently supervised.  The pure decisions
# in this file are covered by synthetic regressions; the default process
# inventory and stop actions are the only Windows-specific operations.

function Get-SupervisionProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property) {
            return $property.Value
        }
    }

    return $null
}

function Normalize-SupervisionProcessName {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $name = [System.IO.Path]::GetFileName($Value.Trim())
    if ($name.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase)) {
        $name = $name.Substring(0, $name.Length - 4)
    }

    return $name.ToUpperInvariant()
}

function Test-SupervisionMitigatedChildMarker {
    param(
        [AllowNull()]
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    # Treat the internal flag as an argument token.  A prefix such as
    # --sharpemu-mitigated-child-copy is not evidence of the child mode.
    return $CommandLine -match '(^|[\s"])--sharpemu-mitigated-child(?=$|[\s"])'
}

function Test-SupervisionCompatibleExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LauncherIdentity,
        [Parameter(Mandatory = $true)]
        [object]$CandidateRecord
    )

    $launcherName = Normalize-SupervisionProcessName -Value ([string]$LauncherIdentity.name)
    $candidateName = Normalize-SupervisionProcessName -Value ([string](Get-SupervisionProperty `
                -Object $CandidateRecord `
                -Names @("name", "Name", "ProcessName")))
    $launcherPath = [string]$LauncherIdentity.executablePath
    $candidatePath = [string](Get-SupervisionProperty `
            -Object $CandidateRecord `
            -Names @("executablePath", "ExecutablePath", "Path"))

    $sameExecutable = -not [string]::IsNullOrWhiteSpace($launcherPath) -and
        -not [string]::IsNullOrWhiteSpace($candidatePath) -and
        [string]::Equals($launcherPath, $candidatePath, [StringComparison]::OrdinalIgnoreCase)
    $sameName = -not [string]::IsNullOrWhiteSpace($launcherName) -and
        -not [string]::IsNullOrWhiteSpace($candidateName) -and
        [string]::Equals($launcherName, $candidateName, [StringComparison]::OrdinalIgnoreCase)

    return [bool]($sameExecutable -or $sameName)
}

function Format-SupervisionStartTimeUtc {
    param(
        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$Value
    )

    # Win32_Process.CreationDate exposes six fractional digits while
    # System.Diagnostics.Process.StartTime can expose seven.  Keep the
    # durable identity at microsecond precision so the two authoritative
    # Windows views describe the same process without weakening PID reuse
    # protection to a coarse wall-clock bucket.
    $ticksPerMicrosecond = [long]([TimeSpan]::TicksPerMillisecond / 1000)
    $normalizedTicks = $Value.ToUniversalTime().Ticks -
        ($Value.ToUniversalTime().Ticks % $ticksPerMicrosecond)
    return ([DateTimeOffset]::new($normalizedTicks, [TimeSpan]::Zero)).ToString("O")
}

function Convert-SupervisionStartTimeToUtc {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($Value -is [DateTimeOffset]) {
        return Format-SupervisionStartTimeUtc -Value $Value
    }

    if ($Value -is [DateTime]) {
        return Format-SupervisionStartTimeUtc -Value ([DateTimeOffset]$Value.ToUniversalTime())
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "Process start time was empty."
    }

    try {
        $parsed = ([DateTimeOffset]::Parse(
                $text,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal))
        return Format-SupervisionStartTimeUtc -Value $parsed
    }
    catch {
        try {
            $converted = ([DateTimeOffset][Management.ManagementDateTimeConverter]::ToDateTime($text))
            return Format-SupervisionStartTimeUtc -Value $converted
        }
        catch {
            throw "Process start time '$text' could not be parsed."
        }
    }
}

function New-SupervisedProcessIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ProcessRecord
    )

    $processIdValue = Get-SupervisionProperty -Object $ProcessRecord -Names @("processId", "ProcessId", "Id")
    if ($null -eq $processIdValue -or [int]$processIdValue -le 0) {
        throw "Process identity did not contain a positive PID."
    }

    $startTimeValue = Get-SupervisionProperty -Object $ProcessRecord -Names @("startTimeUtc", "StartTimeUtc", "CreationDate", "StartTime")
    $startTimeUtc = Convert-SupervisionStartTimeToUtc -Value $startTimeValue
    $name = [string](Get-SupervisionProperty -Object $ProcessRecord -Names @("name", "Name", "ProcessName"))
    $executablePath = [string](Get-SupervisionProperty -Object $ProcessRecord -Names @("executablePath", "ExecutablePath", "Path"))
    $commandLineValue = Get-SupervisionProperty -Object $ProcessRecord -Names @("commandLine", "CommandLine")
    $commandLine = if ($null -eq $commandLineValue) { $null } else { [string]$commandLineValue }
    $mitigatedChildEvidence = if ($null -eq $commandLine) {
        [ordered]@{
            available = $false
            argumentObserved = $false
        }
    }
    else {
        [ordered]@{
            available = $true
            argumentObserved = $commandLine -like "*--sharpemu-mitigated-child*"
        }
    }

    $processId = [int]$processIdValue
    return [pscustomobject][ordered]@{
        processId = $processId
        startTimeUtc = $startTimeUtc
        identityKey = "{0}|{1}" -f $processId, $startTimeUtc
        name = if ([string]::IsNullOrWhiteSpace($name)) { $null } else { $name }
        executablePath = if ([string]::IsNullOrWhiteSpace($executablePath)) { $null } else { $executablePath }
        commandLine = $commandLine
        mitigatedChildEvidence = $mitigatedChildEvidence
    }
}

function New-SupervisedProcessIdentityFromProcess {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Process,
        [AllowNull()]
        [string]$ConfiguredExecutablePath
    )

    $processId = Get-SupervisionProperty -Object $Process -Names @("Id", "ProcessId", "processId")
    if ($null -eq $processId -or [int]$processId -le 0) {
        throw "Started process did not expose a positive PID."
    }

    $startTime = Get-SupervisionProperty -Object $Process -Names @("StartTime", "startTimeUtc", "StartTimeUtc", "CreationDate")
    if ($null -eq $startTime) {
        throw "Started process PID $processId did not expose a start time."
    }

    $name = Get-SupervisionProperty -Object $Process -Names @("ProcessName", "Name", "name")
    if ([string]::IsNullOrWhiteSpace([string]$name)) {
        throw "Started process PID $processId did not expose a process name."
    }

    return New-SupervisedProcessIdentity -ProcessRecord ([pscustomobject][ordered]@{
            processId = [int]$processId
            startTimeUtc = $startTime
            name = [string]$name
            executablePath = $ConfiguredExecutablePath
            commandLine = $null
        })
}

function Merge-SupervisedProcessIdentityEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RecordedIdentity,
        [Parameter(Mandatory = $true)]
        [object]$ObservedIdentity
    )

    foreach ($propertyName in @("name", "executablePath", "commandLine")) {
        if ([string]::IsNullOrWhiteSpace([string]$RecordedIdentity.$propertyName) -and
            -not [string]::IsNullOrWhiteSpace([string]$ObservedIdentity.$propertyName)) {
            $RecordedIdentity.$propertyName = $ObservedIdentity.$propertyName
        }
    }

    if ($null -ne $ObservedIdentity.mitigatedChildEvidence) {
        if ($null -eq $RecordedIdentity.mitigatedChildEvidence) {
            $RecordedIdentity.mitigatedChildEvidence = $ObservedIdentity.mitigatedChildEvidence
        }
        elseif ($ObservedIdentity.mitigatedChildEvidence.argumentObserved) {
            $RecordedIdentity.mitigatedChildEvidence.argumentObserved = $true
            $RecordedIdentity.mitigatedChildEvidence.available = $true
        }
    }

    return $RecordedIdentity
}

function Test-SupervisedProcessIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RecordedIdentity,
        [Parameter(Mandatory = $true)]
        [object]$ObservedProcess
    )

    try {
        $observedIdentity = New-SupervisedProcessIdentity -ProcessRecord $ObservedProcess
    }
    catch {
        return [pscustomobject]@{
            matches = $false
            reason = "identity-unavailable: $($_.Exception.Message)"
            observedIdentity = $null
        }
    }

    if ([int]$RecordedIdentity.processId -ne [int]$observedIdentity.processId) {
        return [pscustomobject]@{
            matches = $false
            reason = "pid-mismatch"
            observedIdentity = $observedIdentity
        }
    }

    if ([string]$RecordedIdentity.startTimeUtc -ne [string]$observedIdentity.startTimeUtc) {
        return [pscustomobject]@{
            matches = $false
            reason = "start-time-mismatch"
            observedIdentity = $observedIdentity
        }
    }

    foreach ($propertyName in @("name", "executablePath")) {
        $recordedValue = [string]$RecordedIdentity.$propertyName
        $observedValue = [string]$observedIdentity.$propertyName
        $valuesMatch = if ($propertyName -eq "name") {
            [string]::Equals(
                (Normalize-SupervisionProcessName -Value $recordedValue),
                (Normalize-SupervisionProcessName -Value $observedValue),
                [StringComparison]::OrdinalIgnoreCase)
        }
        else {
            [string]::Equals($recordedValue, $observedValue, [StringComparison]::OrdinalIgnoreCase)
        }
        if (-not [string]::IsNullOrWhiteSpace($recordedValue) -and
            -not [string]::IsNullOrWhiteSpace($observedValue) -and
            -not $valuesMatch) {
            return [pscustomobject]@{
                matches = $false
                reason = "$propertyName-mismatch"
                observedIdentity = $observedIdentity
            }
        }
    }

    return [pscustomobject]@{
        matches = $true
        reason = "matched"
        observedIdentity = $observedIdentity
    }
}

function Get-SupervisedProcessRootObservation {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Identity,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords
    )

    $matches = @($ProcessRecords | Where-Object {
            [int](Get-SupervisionProperty -Object $_ -Names @("processId", "ProcessId", "Id")) -eq [int]$Identity.processId
        })
    if ($matches.Count -eq 0) {
        return [pscustomobject]@{
            status = "absent"
            record = $null
            mismatch = $null
        }
    }
    if ($matches.Count -ne 1) {
        return [pscustomobject]@{
            status = "mismatch"
            record = $null
            mismatch = "Process inventory contained duplicate records for PID $($Identity.processId)."
        }
    }

    $identityResult = Test-SupervisedProcessIdentity `
        -RecordedIdentity $Identity `
        -ObservedProcess $matches[0]
    if (-not $identityResult.matches) {
        return [pscustomobject]@{
            status = "mismatch"
            record = $matches[0]
            mismatch = $identityResult.reason
        }
    }

    return [pscustomobject]@{
        status = "alive"
        record = $matches[0]
        mismatch = $null
    }
}

function Get-SupervisedProcessTreeRecords {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RootIdentity,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords
    )

    $rootObservation = Get-SupervisedProcessRootObservation `
        -Identity $RootIdentity `
        -ProcessRecords $ProcessRecords
    if ($rootObservation.status -eq "absent") {
        return @()
    }
    if ($rootObservation.status -ne "alive") {
        throw "Cannot enumerate supervised PID $($RootIdentity.processId): $($rootObservation.mismatch)"
    }

    $recordsByPid = @{}
    foreach ($record in $ProcessRecords) {
        $processId = [int](Get-SupervisionProperty -Object $record -Names @("processId", "ProcessId", "Id"))
        if ($processId -le 0) {
            continue
        }
        if ($recordsByPid.ContainsKey($processId)) {
            throw "Process inventory contained duplicate records for PID $processId."
        }
        $recordsByPid[$processId] = $record
    }

    $tree = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $pending = [System.Collections.Generic.Queue[object]]::new()
    $pending.Enqueue($rootObservation.record)

    while ($pending.Count -gt 0) {
        $record = $pending.Dequeue()
        $identity = New-SupervisedProcessIdentity -ProcessRecord $record
        if (-not $seen.Add([string]$identity.identityKey)) {
            continue
        }
        [void]$tree.Add($record)

        $parentProcessId = [int](Get-SupervisionProperty -Object $record -Names @("processId", "ProcessId", "Id"))
        foreach ($candidate in $ProcessRecords) {
            $candidateParentId = Get-SupervisionProperty -Object $candidate -Names @("parentProcessId", "ParentProcessId")
            if ($null -ne $candidateParentId -and [int]$candidateParentId -eq $parentProcessId) {
                $candidateIdentity = New-SupervisedProcessIdentity -ProcessRecord $candidate
                if (-not $seen.Contains([string]$candidateIdentity.identityKey)) {
                    $pending.Enqueue($candidate)
                }
            }
        }
    }

    return @($tree)
}

function Find-SupervisedMitigatedChild {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LauncherIdentity,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords
    )

    $launcherObservation = Get-SupervisedProcessRootObservation `
        -Identity $LauncherIdentity `
        -ProcessRecords $ProcessRecords
    if ($launcherObservation.status -ne "alive") {
        return [pscustomobject]@{
            status = "not-queryable"
            record = $null
            reason = $launcherObservation.mismatch
        }
    }

    $tree = @(Get-SupervisedProcessTreeRecords `
            -RootIdentity $LauncherIdentity `
            -ProcessRecords $ProcessRecords)
    $descendants = @($tree | Where-Object {
            [int](Get-SupervisionProperty -Object $_ -Names @("processId", "ProcessId", "Id")) -ne [int]$LauncherIdentity.processId
        })

    foreach ($descendant in $descendants) {
        if (-not (Test-SupervisionCompatibleExecutable `
                    -LauncherIdentity $LauncherIdentity `
                    -CandidateRecord $descendant)) {
            continue
        }

        $commandLineProperty = $descendant.PSObject.Properties["commandLine"]
        $commandLine = Get-SupervisionProperty -Object $descendant -Names @("commandLine", "CommandLine")
        if ($null -eq $commandLineProperty -or $null -eq $commandLine) {
            return [pscustomobject]@{
                status = "lookup-failure"
                record = $null
                reason = "Mitigated-child command evidence was unavailable for descendant PID $((Get-SupervisionProperty -Object $descendant -Names @('processId', 'ProcessId', 'Id')))."
            }
        }
    }

    $candidates = @($descendants | Where-Object {
            if (-not (Test-SupervisionCompatibleExecutable `
                        -LauncherIdentity $LauncherIdentity `
                        -CandidateRecord $_)) {
                return $false
            }
            $commandLine = [string](Get-SupervisionProperty -Object $_ -Names @("commandLine", "CommandLine"))
            Test-SupervisionMitigatedChildMarker -CommandLine $commandLine
        })
    if ($candidates.Count -eq 0) {
        return [pscustomobject]@{
            status = "not-found"
            record = $null
            reason = $null
        }
    }
    if ($candidates.Count -ne 1) {
        return [pscustomobject]@{
            status = "ambiguous"
            record = $null
            reason = "Found $($candidates.Count) mitigated-child candidates below launcher PID $($LauncherIdentity.processId)."
        }
    }

    return [pscustomobject]@{
        status = "found"
        record = $candidates[0]
        reason = $null
    }
}

function Find-SupervisedMitigatedChildAfterLauncherExit {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LauncherIdentity,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords
    )

    $candidates = [System.Collections.Generic.List[object]]::new()
    foreach ($record in $ProcessRecords) {
        $parentProcessId = Get-SupervisionProperty -Object $record -Names @("parentProcessId", "ParentProcessId")
        if ($null -eq $parentProcessId -or [int]$parentProcessId -ne [int]$LauncherIdentity.processId) {
            continue
        }

        if (-not (Test-SupervisionCompatibleExecutable `
                    -LauncherIdentity $LauncherIdentity `
                    -CandidateRecord $record)) {
            continue
        }

        $commandLineProperty = $record.PSObject.Properties["commandLine"]
        $commandLine = Get-SupervisionProperty -Object $record -Names @("commandLine", "CommandLine")
        if ($null -eq $commandLineProperty -or $null -eq $commandLine) {
            return [pscustomobject]@{
                status = "lookup-failure"
                record = $null
                reason = "Final mitigated-child command evidence was unavailable for descendant PID $((Get-SupervisionProperty -Object $record -Names @('processId', 'ProcessId', 'Id')))."
            }
        }
        if (-not (Test-SupervisionMitigatedChildMarker -CommandLine ([string]$commandLine))) {
            continue
        }

        try {
            $candidateIdentity = New-SupervisedProcessIdentity -ProcessRecord $record
            $launcherStart = [DateTimeOffset]::Parse(
                [string]$LauncherIdentity.startTimeUtc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal)
            $candidateStart = [DateTimeOffset]::Parse(
                [string]$candidateIdentity.startTimeUtc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal)
        }
        catch {
            return [pscustomobject]@{
                status = "lookup-failure"
                record = $null
                reason = "Final mitigated-child identity evidence was unavailable: $($_.Exception.Message)"
            }
        }

        # A direct child whose recorded start predates the launcher cannot be
        # safely associated with this launcher identity.
        if ($candidateStart -le $launcherStart) {
            continue
        }

        [void]$candidates.Add($record)
    }

    if ($candidates.Count -eq 0) {
        return [pscustomobject]@{
            status = "not-found"
            record = $null
            reason = "No compatible mitigated child associated with launcher PID $($LauncherIdentity.processId) was observable in the final inventory."
        }
    }
    if ($candidates.Count -ne 1) {
        return [pscustomobject]@{
            status = "ambiguous"
            record = $null
            reason = "Found $($candidates.Count) compatible mitigated-child candidates associated with launcher PID $($LauncherIdentity.processId)."
        }
    }

    return [pscustomobject]@{
        status = "found"
        record = $candidates[0]
        reason = $null
    }
}

function Get-SupervisionCounterValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ProcessRecord,
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    $value = Get-SupervisionProperty -Object $ProcessRecord -Names $Names
    if ($null -eq $value) {
        throw "Process PID $((Get-SupervisionProperty -Object $ProcessRecord -Names @('processId', 'ProcessId', 'Id'))) did not provide $($Names[0])."
    }

    try {
        $converted = [UInt64]$value
    }
    catch {
        throw "Process PID $((Get-SupervisionProperty -Object $ProcessRecord -Names @('processId', 'ProcessId', 'Id'))) provided an invalid $($Names[0])."
    }
    return $converted
}

function Get-SupervisionTreeCounters {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords
    )

    [UInt64]$workingSetBytes = 0
    [UInt64]$privateBytes = 0
    foreach ($record in $ProcessRecords) {
        $identity = New-SupervisedProcessIdentity -ProcessRecord $record
        $workingSetBytes += Get-SupervisionCounterValue -ProcessRecord $record -Names @("workingSetBytes", "WorkingSet64", "WorkingSetSize")
        $privateBytes += Get-SupervisionCounterValue -ProcessRecord $record -Names @("privateBytes", "PrivateMemorySize64", "PrivatePageCount")
    }

    return [ordered]@{
        processCount = $ProcessRecords.Count
        workingSetBytes = $workingSetBytes
        privateBytes = $privateBytes
    }
}

function Get-DeduplicatedSupervisionCounters {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$Trees
    )

    $recordsByIdentity = @{}
    $sourceTotals = [ordered]@{}
    foreach ($tree in $Trees) {
        $source = [string]$tree.source
        $treeRecords = @($tree.records)
        $sourceTotals[$source] = Get-SupervisionTreeCounters -ProcessRecords $treeRecords
        foreach ($record in $treeRecords) {
            $identity = New-SupervisedProcessIdentity -ProcessRecord $record
            $key = [string]$identity.identityKey
            if (-not $recordsByIdentity.ContainsKey($key)) {
                $recordsByIdentity[$key] = [pscustomobject][ordered]@{
                    identity = $identity
                    workingSetBytes = Get-SupervisionCounterValue -ProcessRecord $record -Names @("workingSetBytes", "WorkingSet64", "WorkingSetSize")
                    privateBytes = Get-SupervisionCounterValue -ProcessRecord $record -Names @("privateBytes", "PrivateMemorySize64", "PrivatePageCount")
                    sources = [System.Collections.Generic.List[string]]::new()
                }
            }
            if (-not $recordsByIdentity[$key].sources.Contains($source)) {
                [void]$recordsByIdentity[$key].sources.Add($source)
            }
        }
    }

    [UInt64]$workingSetBytes = 0
    [UInt64]$privateBytes = 0
    foreach ($record in $recordsByIdentity.Values) {
        $workingSetBytes += [UInt64]$record.workingSetBytes
        $privateBytes += [UInt64]$record.privateBytes
    }

    $processes = @($recordsByIdentity.Values | Sort-Object { $_.identity.processId } | ForEach-Object {
            [ordered]@{
                processId = [int]$_.identity.processId
                startTimeUtc = $_.identity.startTimeUtc
                name = $_.identity.name
                executablePath = $_.identity.executablePath
                commandLine = $_.identity.commandLine
                workingSetBytes = [UInt64]$_.workingSetBytes
                privateBytes = [UInt64]$_.privateBytes
                sources = @($_.sources)
                counterSource = (@($_.sources) -join "+")
            }
        })

    return [pscustomobject][ordered]@{
        processCount = $processes.Count
        workingSetBytes = $workingSetBytes
        privateBytes = $privateBytes
        processes = $processes
        sourceTotals = $sourceTotals
        counterSources = @($sourceTotals.Keys)
    }
}

function Get-ControlledSupervisionMode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExecutablePath,
        [Parameter(Mandatory = $true)]
        [bool]$WindowsHost,
        [AllowNull()]
        [string]$MitigationDisableEnvironmentValue
    )

    if (-not $WindowsHost -or
        [string]::Equals($MitigationDisableEnvironmentValue, "1", [StringComparison]::Ordinal)) {
        return "direct-launch"
    }

    $executableName = Normalize-SupervisionProcessName -Value ([System.IO.Path]::GetFileName($ExecutablePath))
    if ([string]::Equals($executableName, "SHARPEMU", [StringComparison]::OrdinalIgnoreCase)) {
        return "expected-mitigated-child"
    }

    # The controlled runner only infers the relaunch contract for the known
    # SharpEmu CLI.  Other executables remain explicit direct-launch roots.
    return "direct-launch"
}

function New-SupervisionState {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LauncherIdentity,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc,
        [Parameter(Mandatory = $true)]
        [ValidateSet("direct-launch", "expected-mitigated-child")]
        [string]$ExpectedMode
    )

    $state = [pscustomobject][ordered]@{
        launcher = [pscustomobject][ordered]@{
            identity = $LauncherIdentity
            discoveredAtUtc = $ObservedAtUtc
            exitedAtUtc = $null
            alive = $true
            lastRecord = $null
        }
        actualEmulation = [pscustomobject][ordered]@{
            mode = if ($ExpectedMode -eq "direct-launch") { "direct-launch" } else { "unconfirmed" }
            identity = if ($ExpectedMode -eq "direct-launch") { $LauncherIdentity } else { $null }
        }
        expectedMode = $ExpectedMode
        actualChild = $null
        handoffObserved = $false
        monitoringContinuedAfterLauncherExit = $false
        finalChildDiscoveryAttempted = $false
        finalChildDiscoveryAtUtc = $null
        expectedChildNeverConfirmed = $false
        identityMismatches = [System.Collections.Generic.List[object]]::new()
        lookupFailures = [System.Collections.Generic.List[object]]::new()
        knownSupervisedIdentities = [System.Collections.Generic.List[object]]::new()
        cleanupTargets = [System.Collections.Generic.List[object]]::new()
        cleanupEnumerationIncomplete = [System.Collections.Generic.List[object]]::new()
        cleanupFailures = [System.Collections.Generic.List[object]]::new()
    }

    Add-SupervisionKnownIdentity `
        -State $state `
        -Identity $LauncherIdentity `
        -Source "launcher" `
        -ObservedAtUtc $ObservedAtUtc
    return $state
}

function Add-SupervisionKnownIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [object]$Identity,
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc
    )

    $existing = @($State.knownSupervisedIdentities | Where-Object {
            [string]$_.identity.identityKey -eq [string]$Identity.identityKey
        }) | Select-Object -First 1
    if ($null -eq $existing) {
        [void]$State.knownSupervisedIdentities.Add([pscustomobject][ordered]@{
                identity = $Identity
                firstObservedAtUtc = $ObservedAtUtc
                lastObservedAtUtc = $ObservedAtUtc
                sources = [System.Collections.Generic.List[string]]::new()
            })
        $existing = $State.knownSupervisedIdentities[$State.knownSupervisedIdentities.Count - 1]
    }
    else {
        [void](Merge-SupervisedProcessIdentityEvidence `
                -RecordedIdentity $existing.identity `
                -ObservedIdentity $Identity)
        $existing.lastObservedAtUtc = $ObservedAtUtc
    }

    if (-not $existing.sources.Contains($Source)) {
        [void]$existing.sources.Add($Source)
    }
}

function Promote-SupervisedMitigatedChild {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [object]$ProcessRecord,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc
    )

    $childIdentity = New-SupervisedProcessIdentity -ProcessRecord $ProcessRecord
    if ([string]$childIdentity.identityKey -eq [string]$State.launcher.identity.identityKey) {
        throw "Mitigated-child discovery returned the launcher identity instead of a descendant."
    }

    Add-SupervisionKnownIdentity `
        -State $State `
        -Identity $childIdentity `
        -Source "child" `
        -ObservedAtUtc $ObservedAtUtc
    $State.actualChild = [pscustomobject][ordered]@{
        identity = $childIdentity
        discoveredAtUtc = $ObservedAtUtc
        exitedAtUtc = $null
        alive = $true
        lastRecord = $ProcessRecord
        lastCounters = [ordered]@{
            processId = $childIdentity.processId
            startTimeUtc = $childIdentity.startTimeUtc
            workingSetBytes = Get-SupervisionCounterValue -ProcessRecord $ProcessRecord -Names @("workingSetBytes", "WorkingSet64", "WorkingSetSize")
            privateBytes = Get-SupervisionCounterValue -ProcessRecord $ProcessRecord -Names @("privateBytes", "PrivateMemorySize64", "PrivatePageCount")
        }
    }
    $State.actualEmulation.mode = "mitigated-child"
    $State.actualEmulation.identity = $childIdentity
    $State.handoffObserved = $true
}

function Add-SupervisionDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [ValidateSet("identityMismatches", "lookupFailures")]
        [string]$Collection,
        [Parameter(Mandatory = $true)]
        [object]$Record
    )

    [void]$State.$Collection.Add($Record)
}

function Update-SupervisionState {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc
    )

    $launcherObservation = Get-SupervisedProcessRootObservation `
        -Identity $State.launcher.identity `
        -ProcessRecords $ProcessRecords
    if ($launcherObservation.status -eq "mismatch") {
        $diagnostic = [ordered]@{
            process = "launcher"
            processId = $State.launcher.identity.processId
            identity = $State.launcher.identity
            reason = $launcherObservation.mismatch
            observedAtUtc = $ObservedAtUtc
        }
        Add-SupervisionDiagnostic -State $State -Collection "identityMismatches" -Record $diagnostic
        throw "Launcher identity could not be confirmed for PID $($State.launcher.identity.processId): $($launcherObservation.mismatch)"
    }

    if ($launcherObservation.status -eq "alive") {
        $State.launcher.alive = $true
        $State.launcher.lastRecord = $launcherObservation.record
        $observedLauncherIdentity = New-SupervisedProcessIdentity -ProcessRecord $launcherObservation.record
        [void](Merge-SupervisedProcessIdentityEvidence `
                -RecordedIdentity $State.launcher.identity `
                -ObservedIdentity $observedLauncherIdentity)
        Add-SupervisionKnownIdentity `
            -State $State `
            -Identity $observedLauncherIdentity `
            -Source "launcher" `
            -ObservedAtUtc $ObservedAtUtc
    }
    else {
        $State.launcher.alive = $false
        if ($null -eq $State.launcher.exitedAtUtc) {
            $State.launcher.exitedAtUtc = $ObservedAtUtc
        }
    }

    if ($State.expectedMode -eq "expected-mitigated-child" -and
        $State.launcher.alive -and
        $null -eq $State.actualChild) {
        $childResult = Find-SupervisedMitigatedChild `
            -LauncherIdentity $State.launcher.identity `
            -ProcessRecords $ProcessRecords
        if ($childResult.status -in @("lookup-failure", "ambiguous", "not-queryable")) {
            $diagnostic = [ordered]@{
                process = "actual-child-discovery"
                processId = $State.launcher.identity.processId
                reason = $childResult.reason
                observedAtUtc = $ObservedAtUtc
            }
            Add-SupervisionDiagnostic -State $State -Collection "lookupFailures" -Record $diagnostic
            throw "Actual mitigated child could not be safely discovered: $($childResult.reason)"
        }
        if ($childResult.status -eq "found") {
            Promote-SupervisedMitigatedChild `
                -State $State `
                -ProcessRecord $childResult.record `
                -ObservedAtUtc $ObservedAtUtc
        }
    }

    if ($null -ne $State.actualChild) {
        $childObservation = Get-SupervisedProcessRootObservation `
            -Identity $State.actualChild.identity `
            -ProcessRecords $ProcessRecords
        if ($childObservation.status -eq "mismatch") {
            $diagnostic = [ordered]@{
                process = "actual-child"
                processId = $State.actualChild.identity.processId
                identity = $State.actualChild.identity
                reason = $childObservation.mismatch
                observedAtUtc = $ObservedAtUtc
            }
            Add-SupervisionDiagnostic -State $State -Collection "identityMismatches" -Record $diagnostic
            throw "Actual child identity could not be confirmed for PID $($State.actualChild.identity.processId): $($childObservation.mismatch)"
        }
        if ($childObservation.status -eq "alive") {
            $State.actualChild.alive = $true
            $State.actualChild.lastRecord = $childObservation.record
            $observedChildIdentity = New-SupervisedProcessIdentity -ProcessRecord $childObservation.record
            [void](Merge-SupervisedProcessIdentityEvidence `
                    -RecordedIdentity $State.actualChild.identity `
                    -ObservedIdentity $observedChildIdentity)
            Add-SupervisionKnownIdentity `
                -State $State `
                -Identity $observedChildIdentity `
                -Source "child" `
                -ObservedAtUtc $ObservedAtUtc
            $State.actualChild.lastCounters = [ordered]@{
                processId = $State.actualChild.identity.processId
                startTimeUtc = $State.actualChild.identity.startTimeUtc
                workingSetBytes = Get-SupervisionCounterValue -ProcessRecord $childObservation.record -Names @("workingSetBytes", "WorkingSet64", "WorkingSetSize")
                privateBytes = Get-SupervisionCounterValue -ProcessRecord $childObservation.record -Names @("privateBytes", "PrivateMemorySize64", "PrivatePageCount")
            }
        }
        else {
            $State.actualChild.alive = $false
            if ($null -eq $State.actualChild.exitedAtUtc) {
                $State.actualChild.exitedAtUtc = $ObservedAtUtc
            }
        }
    }

    if (-not $State.launcher.alive -and
        $null -ne $State.actualChild -and
        $State.actualChild.alive) {
        $State.monitoringContinuedAfterLauncherExit = $true
    }

    return $State
}

function Invoke-SupervisionFinalChildDiscovery {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc
    )

    if ($State.expectedMode -ne "expected-mitigated-child" -or
        $null -ne $State.actualChild) {
        return [pscustomobject]@{
            status = "not-required"
            record = if ($null -eq $State.actualChild) { $null } else { $State.actualChild.lastRecord }
            reason = $null
        }
    }

    if ($State.finalChildDiscoveryAttempted) {
        return [pscustomobject]@{
            status = if ($State.expectedChildNeverConfirmed) { "not-found" } else { "already-attempted" }
            record = $null
            reason = "Final mitigated-child discovery was already attempted."
        }
    }

    $State.finalChildDiscoveryAttempted = $true
    $State.finalChildDiscoveryAtUtc = $ObservedAtUtc
    $result = Find-SupervisedMitigatedChildAfterLauncherExit `
        -LauncherIdentity $State.launcher.identity `
        -ProcessRecords $ProcessRecords
    if ($result.status -eq "found") {
        Promote-SupervisedMitigatedChild `
            -State $State `
            -ProcessRecord $result.record `
            -ObservedAtUtc $ObservedAtUtc
        return $result
    }

    $State.expectedChildNeverConfirmed = $true
    $diagnostic = [ordered]@{
        process = "expected-actual-child"
        processId = $State.launcher.identity.processId
        identity = $State.launcher.identity
        reason = $result.reason
        status = $result.status
        observedAtUtc = $ObservedAtUtc
    }
    Add-SupervisionDiagnostic -State $State -Collection "lookupFailures" -Record $diagnostic
    return $result
}

function Get-SupervisionLoopDecision {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [object]$Sample
    )

    if ($Sample.anySupervisedProcessAlive) {
        return "continue"
    }
    if ($State.expectedMode -eq "expected-mitigated-child" -and
        $null -eq $State.actualChild) {
        if (-not $State.finalChildDiscoveryAttempted) {
            return "final-child-discovery"
        }
        return "supervision-failure"
    }

    return "process-exited"
}

function Get-SupervisionSample {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessRecords,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc
    )

    Update-SupervisionState `
        -State $State `
        -ProcessRecords $ProcessRecords `
        -ObservedAtUtc $ObservedAtUtc | Out-Null

    $trees = [System.Collections.Generic.List[object]]::new()
    if ($State.launcher.alive) {
        [void]$trees.Add([pscustomobject]@{
                source = "launcher"
                records = @(Get-SupervisedProcessTreeRecords `
                        -RootIdentity $State.launcher.identity `
                        -ProcessRecords $ProcessRecords)
            })
    }
    if ($null -ne $State.actualChild -and $State.actualChild.alive) {
        [void]$trees.Add([pscustomobject]@{
                source = "child"
                records = @(Get-SupervisedProcessTreeRecords `
                        -RootIdentity $State.actualChild.identity `
                        -ProcessRecords $ProcessRecords)
            })
    }

    $aggregate = Get-DeduplicatedSupervisionCounters -Trees @($trees)
    foreach ($tree in $trees) {
        foreach ($record in @($tree.records)) {
            $identity = New-SupervisedProcessIdentity -ProcessRecord $record
            Add-SupervisionKnownIdentity `
                -State $State `
                -Identity $identity `
                -Source ([string]$tree.source) `
                -ObservedAtUtc $ObservedAtUtc
        }
    }
    $actualRecord = $null
    $actualCounters = $null
    if ($State.actualEmulation.mode -eq "mitigated-child") {
        if ($null -ne $State.actualChild -and $State.actualChild.alive) {
            $actualRecord = $State.actualChild.lastRecord
            $actualCounters = $State.actualChild.lastCounters
        }
    }
    elseif ($State.launcher.alive) {
        $actualRecord = $State.launcher.lastRecord
        if ($null -ne $actualRecord) {
            $actualCounters = [ordered]@{
                processId = $State.launcher.identity.processId
                startTimeUtc = $State.launcher.identity.startTimeUtc
                workingSetBytes = Get-SupervisionCounterValue -ProcessRecord $actualRecord -Names @("workingSetBytes", "WorkingSet64", "WorkingSetSize")
                privateBytes = Get-SupervisionCounterValue -ProcessRecord $actualRecord -Names @("privateBytes", "PrivateMemorySize64", "PrivatePageCount")
            }
        }
    }

    $childTreeTotals = if ($aggregate.sourceTotals.Contains("child")) {
        $aggregate.sourceTotals["child"]
    }
    else {
        [ordered]@{
            processCount = 0
            workingSetBytes = [UInt64]0
            privateBytes = [UInt64]0
        }
    }
    $launcherTreeTotals = if ($aggregate.sourceTotals.Contains("launcher")) {
        $aggregate.sourceTotals["launcher"]
    }
    else {
        [ordered]@{
            processCount = 0
            workingSetBytes = [UInt64]0
            privateBytes = [UInt64]0
        }
    }

    return [pscustomobject][ordered]@{
        expectedSupervisionMode = $State.expectedMode
        launcherAlive = [bool]$State.launcher.alive
        actualChildAlive = [bool]($null -ne $State.actualChild -and $State.actualChild.alive)
        anySupervisedProcessAlive = [bool]($State.launcher.alive -or
            ($null -ne $State.actualChild -and $State.actualChild.alive))
        supervisedProcessIds = @($aggregate.processes | ForEach-Object { [int]$_.processId })
        supervisedIdentities = @($aggregate.processes)
        counterSources = @($aggregate.counterSources)
        launcherTree = $launcherTreeTotals
        childTree = $childTreeTotals
        actualEmulationIdentity = $State.actualEmulation.identity
        actualEmulationCounters = $actualCounters
        actualChildIdentity = if ($null -eq $State.actualChild) { $null } else { $State.actualChild.identity }
        actualChildCounters = if ($null -eq $State.actualChild) { $null } else { $State.actualChild.lastCounters }
        knownSupervisedIdentities = @($State.knownSupervisedIdentities | ForEach-Object {
                [ordered]@{
                    identity = $_.identity
                    firstObservedAtUtc = $_.firstObservedAtUtc
                    lastObservedAtUtc = $_.lastObservedAtUtc
                    sources = @($_.sources)
                }
            })
        workingSetBytes = [UInt64]$aggregate.workingSetBytes
        privateBytes = [UInt64]$aggregate.privateBytes
        processCount = [int]$aggregate.processCount
        monitoringContinuedAfterLauncherExit = [bool]$State.monitoringContinuedAfterLauncherExit
    }
}

function Get-TargetProcessInventory {
    param(
        [scriptblock]$QueryAction
    )

    if ($null -eq $QueryAction) {
        $QueryAction = {
            Get-CimInstance Win32_Process -Property `
                ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, `
                WorkingSetSize, PrivatePageCount -ErrorAction Stop
        }
    }

    try {
        $rawRecords = @(& $QueryAction)
    }
    catch {
        throw "SharpEmu process lookup failed: $($_.Exception.Message)"
    }

    if ($rawRecords.Count -eq 0) {
        throw "SharpEmu process lookup failed: the process inventory was empty."
    }

    $records = foreach ($rawRecord in $rawRecords) {
        $processIdValue = Get-SupervisionProperty -Object $rawRecord -Names @("ProcessId", "processId", "Id")
        if ($null -eq $processIdValue -or [int]$processIdValue -le 0) {
            continue
        }
        $startTimeValue = Get-SupervisionProperty -Object $rawRecord -Names @("CreationDate", "startTimeUtc", "StartTimeUtc", "StartTime")
        $startTimeUtc = $null
        if ($null -ne $startTimeValue) {
            try {
                $startTimeUtc = Convert-SupervisionStartTimeToUtc -Value $startTimeValue
            }
            catch {
                $startTimeUtc = $null
            }
        }

        [pscustomobject][ordered]@{
            processId = [int]$processIdValue
            parentProcessId = [int](Get-SupervisionProperty -Object $rawRecord -Names @("ParentProcessId", "parentProcessId"))
            name = [string](Get-SupervisionProperty -Object $rawRecord -Names @("Name", "name", "ProcessName"))
            executablePath = [string](Get-SupervisionProperty -Object $rawRecord -Names @("ExecutablePath", "executablePath", "Path"))
            commandLine = Get-SupervisionProperty -Object $rawRecord -Names @("CommandLine", "commandLine")
            startTimeUtc = $startTimeUtc
            workingSetBytes = Get-SupervisionProperty -Object $rawRecord -Names @("WorkingSetSize", "workingSetBytes", "WorkingSet64")
            privateBytes = Get-SupervisionProperty -Object $rawRecord -Names @("PrivatePageCount", "privateBytes", "PrivateMemorySize64")
        }
    }

    if (@($records).Count -eq 0) {
        throw "SharpEmu process lookup failed: the process inventory contained no valid process identities."
    }

    return @($records)
}

function Stop-ValidatedSupervisedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ProcessRecord,
        [Parameter(Mandatory = $true)]
        [object]$RecordedIdentity,
        [scriptblock]$StopProcessAction
    )

    $identityResult = Test-SupervisedProcessIdentity `
        -RecordedIdentity $RecordedIdentity `
        -ObservedProcess $ProcessRecord
    if (-not $identityResult.matches) {
        throw "Refusing to terminate PID $($RecordedIdentity.processId): $($identityResult.reason)"
    }

    if ($null -ne $StopProcessAction) {
        & $StopProcessAction $ProcessRecord
        return
    }

    $process = Get-Process -Id ([int]$RecordedIdentity.processId) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return
    }

    try {
        $processStartTime = $process.StartTime.ToUniversalTime()
    }
    catch {
        throw "Refusing to terminate PID $($RecordedIdentity.processId): current start time could not be confirmed."
    }
    $currentRecord = [pscustomobject]@{
        processId = [int]$process.Id
        startTimeUtc = ([DateTimeOffset]$processStartTime).ToUniversalTime().ToString("O")
        name = "$($process.ProcessName).exe"
    }
    $currentIdentityResult = Test-SupervisedProcessIdentity `
        -RecordedIdentity $RecordedIdentity `
        -ObservedProcess $currentRecord
    if (-not $currentIdentityResult.matches) {
        throw "Refusing to terminate PID $($RecordedIdentity.processId): current process identity changed ($($currentIdentityResult.reason))."
    }

    $process.Kill()
}

function Stop-ValidatedSupervisedIdentityFallback {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RecordedIdentity,
        [scriptblock]$ProcessLookupAction,
        [scriptblock]$StopProcessAction
    )

    if ($null -eq $ProcessLookupAction) {
        $ProcessLookupAction = {
            param([int]$ProcessId)
            try {
                Get-Process -Id $ProcessId -ErrorAction Stop
            }
            catch {
                if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) {
                    return
                }
                throw "Fallback Get-Process lookup failed for recorded PID ${ProcessId}: $($_.Exception.Message)"
            }
        }
    }

    $currentProcesses = @(& $ProcessLookupAction ([int]$RecordedIdentity.processId))
    if ($currentProcesses.Count -eq 0) {
        return [pscustomobject][ordered]@{
            status = "already-exited"
            processId = $RecordedIdentity.processId
            identity = $RecordedIdentity
            method = "fallback-individual"
        }
    }
    if ($currentProcesses.Count -ne 1) {
        throw "Fallback process lookup returned $($currentProcesses.Count) records for PID $($RecordedIdentity.processId)."
    }

    # This is the final validation immediately before the kill.  The fallback
    # never searches by name and never treats a PID without its recorded start
    # time as a durable target.
    try {
        $currentIdentity = New-SupervisedProcessIdentity -ProcessRecord $currentProcesses[0]
    }
    catch {
        throw "Refusing to terminate PID $($RecordedIdentity.processId): current identity could not be confirmed ($($_.Exception.Message))."
    }
    $identityResult = Test-SupervisedProcessIdentity `
        -RecordedIdentity $RecordedIdentity `
        -ObservedProcess $currentProcesses[0]
    if (-not $identityResult.matches) {
        throw "Refusing to terminate PID $($RecordedIdentity.processId): current process identity changed ($($identityResult.reason))."
    }

    if ($null -ne $StopProcessAction) {
        & $StopProcessAction $currentProcesses[0]
    }
    else {
        $process = $currentProcesses[0]
        if ($null -eq $process.PSObject.Methods["Kill"]) {
            throw "Fallback process PID $($RecordedIdentity.processId) did not expose a kill operation."
        }
        $process.Kill()
        if ($null -ne $process.PSObject.Methods["WaitForExit"]) {
            [void]$process.WaitForExit(5000)
        }
    }

    return [pscustomobject][ordered]@{
        status = "terminated"
        processId = $RecordedIdentity.processId
        identity = $RecordedIdentity
        method = "fallback-individual"
    }
}

function Stop-SupervisedKnownIdentitiesFallback {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [string]$Reason,
        [Parameter(Mandatory = $true)]
        [object[]]$Identities,
        [scriptblock]$ProcessLookupAction,
        [scriptblock]$StopProcessAction,
        [bool]$DescendantEnumerationIncomplete = $true
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()
    # The normal observation order is root to descendant.  Reverse it for
    # fallback cleanup so a known descendant gets an independent attempt
    # before its parent is terminated.
    for ($index = $Identities.Count - 1; $index -ge 0; $index--) {
        $identity = $Identities[$index]
        if ($null -eq $identity -or -not $seen.Add([string]$identity.identityKey)) {
            continue
        }

        $target = [ordered]@{
            attemptedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
            reason = $Reason
            method = "fallback-individual"
            descendantEnumerationIncomplete = $DescendantEnumerationIncomplete
            identity = $identity
            processId = $identity.processId
            status = $null
            error = $null
        }
        try {
            $result = Stop-ValidatedSupervisedIdentityFallback `
                -RecordedIdentity $identity `
                -ProcessLookupAction $ProcessLookupAction `
                -StopProcessAction $StopProcessAction
            $target.status = $result.status
            [void]$results.Add($result)
        }
        catch {
            $target.status = "failed"
            $target.error = $_.Exception.Message
            [void]$failures.Add("PID $($identity.processId): $($_.Exception.Message)")
            [void]$State.cleanupFailures.Add($target)
        }
        [void]$State.cleanupTargets.Add($target)
    }

    return [pscustomobject][ordered]@{
        results = @($results)
        failures = @($failures)
    }
}

function Stop-SupervisedProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RootIdentity,
        [scriptblock]$InventoryAction,
        [scriptblock]$StopProcessAction,
        [scriptblock]$SleepAction,
        [int]$TimeoutMilliseconds = 10000
    )

    if ($null -eq $InventoryAction) {
        $InventoryAction = { Get-TargetProcessInventory }
    }
    if ($null -eq $SleepAction) {
        $SleepAction = { param([int]$Milliseconds) Start-Sleep -Milliseconds $Milliseconds }
    }

    $startedAt = [DateTimeOffset]::UtcNow
    $attempts = 0
    do {
        $attempts++
        try {
            $records = @(& $InventoryAction)
            $rootObservation = Get-SupervisedProcessRootObservation `
                -Identity $RootIdentity `
                -ProcessRecords $records
        }
        catch {
            throw [System.InvalidOperationException]::new(
                "supervision-inventory-unavailable: $($_.Exception.Message)",
                $_.Exception)
        }
        if ($rootObservation.status -eq "absent") {
            return [pscustomobject][ordered]@{
                status = "already-exited"
                processId = $RootIdentity.processId
                identity = $RootIdentity
                attempts = $attempts
            }
        }
        if ($rootObservation.status -ne "alive") {
            throw "Refusing to terminate supervised PID $($RootIdentity.processId): $($rootObservation.mismatch)"
        }

        try {
            $tree = @(Get-SupervisedProcessTreeRecords `
                    -RootIdentity $RootIdentity `
                    -ProcessRecords $records)
        }
        catch {
            throw [System.InvalidOperationException]::new(
                "supervision-inventory-unavailable: $($_.Exception.Message)",
                $_.Exception)
        }
        # Descendants are handled before the root so that a launcher cannot
        # disappear before the independently tracked child is considered.
        for ($index = $tree.Count - 1; $index -ge 0; $index--) {
            Stop-ValidatedSupervisedProcess `
                -ProcessRecord $tree[$index] `
                -RecordedIdentity (New-SupervisedProcessIdentity -ProcessRecord $tree[$index]) `
                -StopProcessAction $StopProcessAction
        }

        try {
            $remaining = @(& $InventoryAction)
            $remainingObservation = Get-SupervisedProcessRootObservation `
                -Identity $RootIdentity `
                -ProcessRecords $remaining
        }
        catch {
            throw [System.InvalidOperationException]::new(
                "supervision-inventory-unavailable: $($_.Exception.Message)",
                $_.Exception)
        }
        if ($remainingObservation.status -eq "absent") {
            return [pscustomobject][ordered]@{
                status = "terminated"
                processId = $RootIdentity.processId
                identity = $RootIdentity
                attempts = $attempts
            }
        }
        if ($remainingObservation.status -ne "alive") {
            throw "Supervised PID $($RootIdentity.processId) changed identity during cleanup: $($remainingObservation.mismatch)"
        }

        if (([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds -ge $TimeoutMilliseconds) {
            throw "Failed to stop supervised process tree rooted at PID $($RootIdentity.processId) within $TimeoutMilliseconds ms."
        }
        & $SleepAction 250
    } while ($true)
}

function Stop-SupervisedRoots {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [string]$Reason,
        [scriptblock]$InventoryAction,
        [scriptblock]$StopProcessAction,
        [scriptblock]$ProcessLookupAction,
        [scriptblock]$SleepAction,
        [int]$TimeoutMilliseconds = 10000
    )

    $identities = @(
        $State.launcher.identity
        if ($null -ne $State.actualChild) {
            $State.actualChild.identity
        }
    )
    $failures = [System.Collections.Generic.List[string]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $fallbackUsed = $false
    foreach ($identity in $identities) {
        if ($null -eq $identity) {
            continue
        }
        $target = [ordered]@{
            attemptedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
            reason = $Reason
            method = "tree-inventory"
            descendantEnumerationIncomplete = $false
            identity = $identity
            processId = $identity.processId
            status = $null
            error = $null
        }
        try {
            $result = Stop-SupervisedProcessTree `
                -RootIdentity $identity `
                -InventoryAction $InventoryAction `
                -StopProcessAction $StopProcessAction `
                -SleepAction $SleepAction `
                -TimeoutMilliseconds $TimeoutMilliseconds
            $target.status = $result.status
            [void]$results.Add($result)
        }
        catch {
            if ($_.Exception.Message -like "supervision-inventory-unavailable:*") {
                $fallbackUsed = $true
                $incompleteRecord = [ordered]@{
                    attemptedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
                    reason = $Reason
                    rootIdentity = $identity
                    error = $_.Exception.Message
                    knownIdentityCount = $State.knownSupervisedIdentities.Count
                }
                [void]$State.cleanupEnumerationIncomplete.Add($incompleteRecord)
                $target.status = "fallback-individual"
                $target.method = "tree-inventory-failed"
                $target.descendantEnumerationIncomplete = $true
                $target.error = $_.Exception.Message
                [void]$State.cleanupTargets.Add($target)

                $knownIdentities = @($State.knownSupervisedIdentities | ForEach-Object { $_.identity })
                if ($knownIdentities.Count -eq 0) {
                    $knownIdentities = @($identities | Where-Object { $null -ne $_ })
                }
                if ($knownIdentities.Count -eq 0) {
                    $failure = "No individually known supervised identities were available for fallback cleanup."
                    [void]$failures.Add($failure)
                    [void]$State.cleanupFailures.Add([ordered]@{
                            attemptedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
                            reason = $Reason
                            method = "fallback-individual"
                            descendantEnumerationIncomplete = $true
                            identity = $null
                            processId = $null
                            status = "failed"
                            error = $failure
                        })
                    break
                }
                $fallback = Stop-SupervisedKnownIdentitiesFallback `
                    -State $State `
                    -Reason $Reason `
                    -Identities $knownIdentities `
                    -ProcessLookupAction $ProcessLookupAction `
                    -StopProcessAction $StopProcessAction
                foreach ($fallbackResult in @($fallback.results)) {
                    [void]$results.Add($fallbackResult)
                }
                foreach ($fallbackFailure in @($fallback.failures)) {
                    [void]$failures.Add([string]$fallbackFailure)
                }
                break
            }

            $target.status = "failed"
            $target.error = $_.Exception.Message
            [void]$failures.Add("PID $($identity.processId): $($_.Exception.Message)")
            [void]$State.cleanupFailures.Add($target)
        }
        if (-not $fallbackUsed) {
            [void]$State.cleanupTargets.Add($target)
        }
    }

    if ($failures.Count -gt 0) {
        throw "Supervised process cleanup failed: $($failures -join ' | ')"
    }

    return @($results)
}
