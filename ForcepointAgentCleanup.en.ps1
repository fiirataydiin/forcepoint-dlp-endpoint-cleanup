#requires -Version 5.1

<#
.SYNOPSIS
    Forcepoint DLP - removes stale (not reporting) agent records from the Endpoint Status list.

.DESCRIPTION
    Based on the "Endpoint Status" query in ForcepointDlpHealth.ps1 (PA_DYNAMIC_STATUS +
    PA_DYNAMIC_STATUS_PROPS, identical to the FSM console Status > Endpoint Status screen).

    Flow:
      1. Connects to SQL Server (sqlcmd.exe, Windows or SQL Login).
      2. Shows the total number of agents in the system.
      3. Lists agents that have not reported for 7 / 15 / 30 days
         (PA_DYNAMIC_STATUS.UPDATE_DATE = 'Last Update' in FSM).
      4. Asks how old the records to delete must be (7 / 15 / 30 days).
      5. Requires a DOUBLE CONFIRMATION: first Y/N, then typing the number of records to delete.
      6. Backs up the records to be deleted as a CSV on the desktop, then deletes them in a
         SINGLE transaction (PROPS first, then STATUS) and reports the number of deleted agents.

    NOTE: This script ONLY deletes Endpoint Status (live status) records. If an agent connects
    to FSM again, its record is recreated. It does NOT uninstall agents from endpoint machines.

    Author: FIRAT AYDIN

.EXAMPLE
    .\ForcepointAgentCleanup.en.ps1

.EXAMPLE
    .\ForcepointAgentCleanup.en.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa
#>

[CmdletBinding()]
param(
    [string]$SqlServerInstance = '',

    [string]$SqlDatabaseName = 'wbsn-data-security',

    [ValidateSet('Windows', 'SqlLogin')]
    [string]$SqlAuthMode = 'Windows',

    [string]$SqlUserName = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$script:Thresholds = @(7, 15, 30)
$script:SecurePassword = $null

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

# Runs the given SQL with sqlcmd and returns the output lines. Throws on error.
function Invoke-FpSql {
    param([Parameter(Mandatory)] [string]$Sql)

    $sqlCmdExe = Get-Command 'sqlcmd.exe' -ErrorAction SilentlyContinue
    if (-not $sqlCmdExe) { throw 'sqlcmd.exe was not found in PATH (SQL Server Command Line Utilities or SSMS is required).' }

    $tempDir = Join-Path $env:ProgramData 'FpDlpHealthTemp'
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $sqlFile = Join-Path $tempDir 'fp_agent_cleanup.sql'
    $outFile = Join-Path $tempDir 'fp_agent_cleanup_result.txt'
    Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
    Set-Content -LiteralPath $sqlFile -Value $Sql -Encoding UTF8

    $sqlArgs = [System.Collections.Generic.List[string]]::new()
    [void]$sqlArgs.AddRange([string[]]@('-S', $SqlServerInstance, '-d', $SqlDatabaseName, '-i', $sqlFile, '-o', $outFile, '-h', '-1', '-W', '-s', '|', '-f', '65001', '-b'))

    $plainPassword = $null
    $passwordPointer = [IntPtr]::Zero
    try {
        if ($SqlAuthMode -eq 'Windows') {
            [void]$sqlArgs.Add('-E')
        }
        else {
            if (-not $script:SecurePassword) {
                $script:SecurePassword = Read-Host -Prompt "SQL Server password ($SqlUserName)" -AsSecureString
            }
            $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:SecurePassword)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
            [void]$sqlArgs.Add('-U'); [void]$sqlArgs.Add($SqlUserName)
            [void]$sqlArgs.Add('-P'); [void]$sqlArgs.Add($plainPassword)
        }
        $null = & $sqlCmdExe.Source $sqlArgs.ToArray() 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $plainPassword = $null
        if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
    }

    $lines = @()
    if (Test-Path -LiteralPath $outFile) { $lines = @(Get-Content -LiteralPath $outFile -Encoding UTF8) }
    Remove-Item -Path $sqlFile, $outFile -Force -ErrorAction SilentlyContinue

    $errLines = @($lines | Where-Object { $_ -match 'Msg \d+|Login failed|Cannot open|^ERROR\|' })
    if ($exitCode -ne 0 -or $errLines.Count -gt 0) {
        throw "sqlcmd failed (exit code $exitCode). $($errLines -join ' | ')"
    }
    return ,@($lines | Where-Object { $_.Trim() -ne '' })
}

# Reads Endpoint Status records (same source as the ENDPOINT_STATUS query in ForcepointDlpHealth.ps1).
# The ID is also fetched so that deletion is done by ID list and limited to the records that were
# SHOWN and CONFIRMED (agents that reconnect between listing and deletion are not affected).
function Get-FpEndpointStatus {
    $sql = @'
SET NOCOUNT ON;
IF OBJECT_ID('PA_DYNAMIC_STATUS','U') IS NULL OR OBJECT_ID('PA_DYNAMIC_STATUS_PROPS','U') IS NULL
BEGIN
    SELECT 'ERROR|PA_DYNAMIC_STATUS / PA_DYNAMIC_STATUS_PROPS tables not found.';
    RETURN;
END
SELECT
    CAST(s.ID AS NVARCHAR(40)) + '|' +
    ISNULL(REPLACE(s.[KEY],'|','/'),'') + '|' +
    ISNULL(CONVERT(NVARCHAR(19), s.UPDATE_DATE, 120),'') + '|' +
    ISNULL(CAST(DATEDIFF(day, s.UPDATE_DATE, GETDATE()) AS NVARCHAR(10)),'') + '|' +
    ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_IPAddress' THEN p.STR_VALUE END),'|','/'),'') + '|' +
    ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_LoggedInUsers' THEN p.STR_VALUE END),'|','/'),'') + '|' +
    ISNULL(CAST(MAX(CASE WHEN p.NAME='eps_os_Synced' THEN p.INT_VALUE END) AS NVARCHAR(5)),'') + '|' +
    ISNULL(REPLACE(MAX(CASE WHEN p.NAME='eps_os_AgentInstallationVersion' THEN p.STR_VALUE END),'|','/'),'')
FROM PA_DYNAMIC_STATUS s
LEFT JOIN PA_DYNAMIC_STATUS_PROPS p ON p.DYNAMIC_STATUS_ID = s.ID
GROUP BY s.ID, s.[KEY], s.UPDATE_DATE
ORDER BY s.UPDATE_DATE;
'@
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($l in (Invoke-FpSql -Sql $sql)) {
        $p = $l -split '\|'
        if ($p.Count -lt 8 -or $p[0] -notmatch '^\d+$') { continue }
        [void]$rows.Add([pscustomobject]@{
            Id            = [long]$p[0]
            Hostname      = $p[1]
            LastUpdate    = $p[2]
            DaysAgo       = if ($p[3] -match '^-?\d+$') { [int]$p[3] } else { $null }
            IpAddress     = $p[4]
            LoggedInUsers = $p[5]
            Synced        = $p[6]
            Version       = $p[7]
        })
    }
    return ,$rows.ToArray()
}

function Show-EndpointTable {
    param([object[]]$Items)
    $Items | Sort-Object DaysAgo -Descending |
        Format-Table @{ L = 'Hostname'; E = { $_.Hostname } },
                     @{ L = 'IP'; E = { $_.IpAddress } },
                     @{ L = 'Last Update'; E = { $_.LastUpdate } },
                     @{ L = 'Days'; E = { $_.DaysAgo }; A = 'Right' },
                     @{ L = 'Sync'; E = { if ($_.Synced -eq '1') { 'Yes' } elseif ($_.Synced -eq '0') { 'No' } else { '' } } },
                     @{ L = 'User'; E = { $_.LoggedInUsers } },
                     @{ L = 'Version'; E = { $_.Version } } -AutoSize | Out-Host
}

# ------------------------------------------------------------------------------------
# 1) Connection details
# ------------------------------------------------------------------------------------
Write-Section -Title 'FORCEPOINT DLP - ENDPOINT STATUS CLEANUP'

if ([string]::IsNullOrWhiteSpace($SqlServerInstance)) {
    $SqlServerInstance = Read-Host -Prompt 'SQL Server name (e.g. SERVERNAME or SERVERNAME\INSTANCE)'
}
if (-not $PSBoundParameters.ContainsKey('SqlAuthMode')) {
    Write-Host ''
    Write-Host 'Select authentication type:'
    Write-Host '  1 = Windows authentication (default, uses the current session)'
    Write-Host '  2 = SQL Server authentication (username/password)'
    $authChoice = Read-Host -Prompt 'Your choice [1]'
    if ($authChoice.Trim() -eq '2') { $SqlAuthMode = 'SqlLogin' }
}
if ($SqlAuthMode -eq 'SqlLogin' -and [string]::IsNullOrWhiteSpace($SqlUserName)) {
    $SqlUserName = Read-Host -Prompt 'SQL Server username'
}

# ------------------------------------------------------------------------------------
# 2) Read Endpoint Status + summary
# ------------------------------------------------------------------------------------
try {
    $endpoints = Get-FpEndpointStatus
}
catch {
    Write-Host "SQL Server connection / query FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "SQL Server connection: SUCCESSFUL ($SqlServerInstance / $SqlDatabaseName)" -ForegroundColor Green

Write-Section -Title 'AGENT SUMMARY'
Write-Host ("Total agents in the system        : {0}" -f @($endpoints).Count) -ForegroundColor White
$staleByThreshold = @{}
foreach ($t in $script:Thresholds) {
    $staleByThreshold[$t] = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $t })
    $color = if ($staleByThreshold[$t].Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("Agents not reporting for {0,2}+ days : {1}" -f $t, $staleByThreshold[$t].Count) -ForegroundColor $color
}
Write-Host '(Counts are cumulative: 7+ days = sum of the 7-14, 15-29 and 30+ day lists.)' -ForegroundColor DarkGray
$noDate = @($endpoints | Where-Object { $null -eq $_.DaysAgo })
if ($noDate.Count -gt 0) {
    Write-Host ("Agents without Last Update        : {0} (never included in deletion)" -f $noDate.Count) -ForegroundColor DarkYellow
}

# Lists: each host is shown only once, under the highest threshold it belongs to
# (30+ days, 15-29 days, 7-14 days). The summary counts above are cumulative.
$bands = @(
    @{ Title = 'AGENTS NOT REPORTING FOR 30+ DAYS'; Min = 30; Max = [int]::MaxValue },
    @{ Title = 'AGENTS NOT REPORTING FOR 15 - 29 DAYS'; Min = 15; Max = 29 },
    @{ Title = 'AGENTS NOT REPORTING FOR 7 - 14 DAYS'; Min = 7; Max = 14 }
)
foreach ($b in $bands) {
    $items = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $b.Min -and $_.DaysAgo -le $b.Max })
    Write-Section -Title "$($b.Title) ($($items.Count))"
    if ($items.Count -gt 0) { Show-EndpointTable -Items $items } else { Write-Host 'No records.' -ForegroundColor Green }
}

if ($staleByThreshold[$script:Thresholds[0]].Count -eq 0) {
    Write-Host ''
    Write-Host "No agents older than $($script:Thresholds[0]) days, nothing to delete." -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------------------------------
# 3) Threshold selection
# ------------------------------------------------------------------------------------
Write-Section -Title 'DELETION'
Write-Host 'Delete Endpoint Status machines older than how many days?'
for ($i = 0; $i -lt $script:Thresholds.Count; $i++) {
    $t = $script:Thresholds[$i]
    Write-Host ("  {0} = Agents older than {1} days ({2} agents)" -f ($i + 1), $t, $staleByThreshold[$t].Count)
}
Write-Host '  0 = Cancel (nothing is deleted)'
$choice = (Read-Host -Prompt 'Your choice').Trim()
if ($choice -notmatch '^[1-3]$') {
    Write-Host 'Operation cancelled, no records were deleted.' -ForegroundColor DarkYellow
    exit 0
}
$selectedDays = $script:Thresholds[[int]$choice - 1]
$toDelete = @($staleByThreshold[$selectedDays])
if ($toDelete.Count -eq 0) {
    Write-Host "No agents older than $selectedDays days, nothing to delete." -ForegroundColor Green
    exit 0
}

Write-Host ''
Write-Host "$($toDelete.Count) agents older than $selectedDays days will be deleted:" -ForegroundColor Yellow
Show-EndpointTable -Items $toDelete

# ------------------------------------------------------------------------------------
# 4) Double confirmation
# ------------------------------------------------------------------------------------
$confirm1 = (Read-Host -Prompt "CONFIRMATION 1: Do you want to delete $($toDelete.Count) agent records older than $selectedDays days? (Y/N)").Trim()
if ($confirm1 -notin @('Y', 'y', 'Yes', 'yes', 'YES')) {
    Write-Host 'Operation cancelled, no records were deleted.' -ForegroundColor DarkYellow
    exit 0
}
Write-Host ''
Write-Host 'WARNING: This operation cannot be undone (a CSV backup will be saved to the desktop).' -ForegroundColor Red
$confirm2 = (Read-Host -Prompt "CONFIRMATION 2: Please confirm again. Type the number of records to delete ($($toDelete.Count))").Trim()
if ($confirm2 -ne [string]$toDelete.Count) {
    Write-Host 'Second confirmation did not match. Operation cancelled, no records were deleted.' -ForegroundColor DarkYellow
    exit 0
}

# ------------------------------------------------------------------------------------
# 5) Backup + deletion
# ------------------------------------------------------------------------------------
$desktop = [Environment]::GetFolderPath('Desktop')
$backupFile = Join-Path $desktop ("Forcepoint_EndpointStatus_Deleted_{0}days_{1}.csv" -f $selectedDays, (Get-Date -Format 'yyyyMMdd_HHmmss'))
$toDelete | Select-Object Id, Hostname, IpAddress, LastUpdate, DaysAgo, Synced, LoggedInUsers, Version |
    Export-Csv -LiteralPath $backupFile -NoTypeInformation -Encoding UTF8
Write-Host "Backup saved: $backupFile" -ForegroundColor Cyan

# IDs are safe: only [long] values are written into the SQL.
$idValues = ($toDelete | ForEach-Object { "($([long]$_.Id))" }) -join ",`r`n"
$deleteSql = @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @ids TABLE (ID BIGINT PRIMARY KEY);
INSERT INTO @ids (ID) VALUES
$idValues;

-- Safety: records updated more recently than the selected threshold (reconnected meanwhile) are not deleted.
DELETE i FROM @ids i
WHERE NOT EXISTS (SELECT 1 FROM PA_DYNAMIC_STATUS s
                  WHERE s.ID = i.ID AND s.UPDATE_DATE < DATEADD(day, -$selectedDays, GETDATE()));

DECLARE @props INT, @status INT;
BEGIN TRY
    BEGIN TRANSACTION;
    DELETE p FROM PA_DYNAMIC_STATUS_PROPS p INNER JOIN @ids i ON i.ID = p.DYNAMIC_STATUS_ID;
    SET @props = @@ROWCOUNT;
    DELETE s FROM PA_DYNAMIC_STATUS s INNER JOIN @ids i ON i.ID = s.ID;
    SET @status = @@ROWCOUNT;
    COMMIT TRANSACTION;
    SELECT 'RESULT|' + CAST(@status AS NVARCHAR(20)) + '|' + CAST(@props AS NVARCHAR(20));
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    SELECT 'ERROR|' + ERROR_MESSAGE();
END CATCH
"@

try {
    $out = Invoke-FpSql -Sql $deleteSql
}
catch {
    Write-Host "Deletion FAILED, transaction rolled back: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$resultLine = @($out | Where-Object { $_ -like 'RESULT|*' }) | Select-Object -First 1
if (-not $resultLine) {
    Write-Host "Could not read the deletion result. Output: $($out -join ' | ')" -ForegroundColor Red
    exit 1
}
$r = $resultLine -split '\|'
$deletedCount = [int]$r[1]

Write-Section -Title 'RESULT'
Write-Host "Deleted agents   : $deletedCount" -ForegroundColor Green
Write-Host "Deleted property rows (PA_DYNAMIC_STATUS_PROPS): $($r[2])" -ForegroundColor DarkGray
if ($deletedCount -lt $toDelete.Count) {
    Write-Host "$($toDelete.Count - $deletedCount) records were not deleted (reconnected between listing and deletion, or already deleted)." -ForegroundColor DarkYellow
}
Write-Host "Remaining agents : $(@($endpoints).Count - $deletedCount)" -ForegroundColor White
Write-Host "Backup file      : $backupFile" -ForegroundColor Cyan
