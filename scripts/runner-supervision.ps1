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
        if (-not [string]::IsNullOrWhiteSpace($recordedValue) -and
            -not [string]::IsNullOrWhiteSpace($observedValue) -and
            $recordedValue -ne $observedValue) {
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

    $launcherName = [string]$LauncherIdentity.name
    $launcherPath = [string]$LauncherIdentity.executablePath
    foreach ($descendant in $descendants) {
        $descendantName = [string](Get-SupervisionProperty -Object $descendant -Names @("name", "Name", "ProcessName"))
        $descendantPath = [string](Get-SupervisionProperty -Object $descendant -Names @("executablePath", "ExecutablePath", "Path"))
        $sameExecutable = (-not [string]::IsNullOrWhiteSpace($launcherPath) -and
            -not [string]::IsNullOrWhiteSpace($descendantPath) -and
            $launcherPath -eq $descendantPath)
        $sameName = (-not [string]::IsNullOrWhiteSpace($launcherName) -and
            -not [string]::IsNullOrWhiteSpace($descendantName) -and
            $launcherName -eq $descendantName)
        if (-not ($sameExecutable -or $sameName)) {
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
            $commandLine = [string](Get-SupervisionProperty -Object $_ -Names @("commandLine", "CommandLine"))
            $commandLine -like "*--sharpemu-mitigated-child*"
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

function New-SupervisionState {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LauncherIdentity,
        [Parameter(Mandatory = $true)]
        [string]$ObservedAtUtc
    )

    return [pscustomobject][ordered]@{
        launcher = [pscustomobject][ordered]@{
            identity = $LauncherIdentity
            discoveredAtUtc = $ObservedAtUtc
            exitedAtUtc = $null
            alive = $true
            lastRecord = $null
        }
        actualEmulation = [pscustomobject][ordered]@{
            mode = "direct-launch"
            identity = $LauncherIdentity
        }
        actualChild = $null
        handoffObserved = $false
        monitoringContinuedAfterLauncherExit = $false
        identityMismatches = [System.Collections.Generic.List[object]]::new()
        lookupFailures = [System.Collections.Generic.List[object]]::new()
        cleanupTargets = [System.Collections.Generic.List[object]]::new()
        cleanupFailures = [System.Collections.Generic.List[object]]::new()
    }
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
    }
    else {
        $State.launcher.alive = $false
        if ($null -eq $State.launcher.exitedAtUtc) {
            $State.launcher.exitedAtUtc = $ObservedAtUtc
        }
    }

    if ($State.launcher.alive -and $null -eq $State.actualChild) {
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
            $childIdentity = New-SupervisedProcessIdentity -ProcessRecord $childResult.record
            $State.actualChild = [pscustomobject][ordered]@{
                identity = $childIdentity
                discoveredAtUtc = $ObservedAtUtc
                exitedAtUtc = $null
                alive = $true
                lastRecord = $childResult.record
                lastCounters = [ordered]@{
                    processId = $childIdentity.processId
                    startTimeUtc = $childIdentity.startTimeUtc
                    workingSetBytes = Get-SupervisionCounterValue -ProcessRecord $childResult.record -Names @("workingSetBytes", "WorkingSet64", "WorkingSetSize")
                    privateBytes = Get-SupervisionCounterValue -ProcessRecord $childResult.record -Names @("privateBytes", "PrivateMemorySize64", "PrivatePageCount")
                }
            }
            $State.actualEmulation.mode = "mitigated-child"
            $State.actualEmulation.identity = $childIdentity
            $State.handoffObserved = $true
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
        $records = @(& $InventoryAction)
        $rootObservation = Get-SupervisedProcessRootObservation `
            -Identity $RootIdentity `
            -ProcessRecords $records
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

        $tree = @(Get-SupervisedProcessTreeRecords `
                -RootIdentity $RootIdentity `
                -ProcessRecords $records)
        # Descendants are handled before the root so that a launcher cannot
        # disappear before the independently tracked child is considered.
        for ($index = $tree.Count - 1; $index -ge 0; $index--) {
            Stop-ValidatedSupervisedProcess `
                -ProcessRecord $tree[$index] `
                -RecordedIdentity (New-SupervisedProcessIdentity -ProcessRecord $tree[$index]) `
                -StopProcessAction $StopProcessAction
        }

        $remaining = @(& $InventoryAction)
        $remainingObservation = Get-SupervisedProcessRootObservation `
            -Identity $RootIdentity `
            -ProcessRecords $remaining
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
    foreach ($identity in $identities) {
        if ($null -eq $identity) {
            continue
        }
        $target = [ordered]@{
            attemptedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
            reason = $Reason
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
            $target.status = "failed"
            $target.error = $_.Exception.Message
            [void]$failures.Add("PID $($identity.processId): $($_.Exception.Message)")
            [void]$State.cleanupFailures.Add($target)
        }
        [void]$State.cleanupTargets.Add($target)
    }

    if ($failures.Count -gt 0) {
        throw "Supervised process cleanup failed: $($failures -join ' | ')"
    }

    return @($results)
}
