#requires -Version 5.1

<#
.SYNOPSIS
    Forcepoint DLP - Endpoint Status listesinden eski (erisemeyen) agent kayitlarini temizler.

.DESCRIPTION
    ForcepointDlpHealth.ps1 icindeki "Endpoint Status" sorgusunu (PA_DYNAMIC_STATUS +
    PA_DYNAMIC_STATUS_PROPS, FSM konsolu Status > Endpoint Status ekraniyla birebir ayni)
    temel alir.

    Akis:
      1. SQL Server'a baglanir (sqlcmd.exe, Windows veya SQL Login).
      2. Sistemdeki toplam agent sayisini verir.
      3. 7 / 15 / 30 gundur erismeyen agentlari (PA_DYNAMIC_STATUS.UPDATE_DATE = FSM'deki
         'Last Update') listeler.
      4. Kac gunden eski kayitlarin silinecegini sorar (7 / 15 / 30).
      5. CIFT ONAY alir: once E/H, sonra silinecek kayit sayisinin elle yazilmasi.
      6. Silinecek kayitlari once masaustune CSV olarak yedekler, sonra TEK bir transaction
         icinde siler (once PROPS, sonra STATUS) ve silinen agent sayisini verir.

    NOT: Bu script SADECE Endpoint Status (canli durum) kayitlarini siler. Agent tekrar
    FSM'e baglanirsa kaydi yeniden olusur. Endpoint makinelerden agent KALDIRMAZ.

    Hazirlayan: FIRAT AYDIN / Barikat Siber Guvenlik

.EXAMPLE
    .\ForcepointAgentCleanup.ps1

.EXAMPLE
    .\ForcepointAgentCleanup.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa
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

# sqlcmd ile verilen SQL'i calistirir, cikti satirlarini dondurur. Hata olursa throw eder.
function Invoke-FpSql {
    param([Parameter(Mandatory)] [string]$Sql)

    $sqlCmdExe = Get-Command 'sqlcmd.exe' -ErrorAction SilentlyContinue
    if (-not $sqlCmdExe) { throw 'sqlcmd.exe PATH icinde bulunamadi (SQL Server Command Line Utilities veya SSMS gerekli).' }

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
                $script:SecurePassword = Read-Host -Prompt "SQL Server parolasi ($SqlUserName)" -AsSecureString
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
        throw "sqlcmd basarisiz (cikis kodu $exitCode). $($errLines -join ' | ')"
    }
    return ,@($lines | Where-Object { $_.Trim() -ne '' })
}

# Endpoint Status kayitlarini okur (ForcepointDlpHealth.ps1 ENDPOINT_STATUS sorgusuyla ayni kaynak).
# ID ayrica cekilir: silme islemi kullaniciya GOSTERILEN ve ONAYLANAN kayitlarla sinirli kalsin diye
# ID listesi uzerinden yapilir (liste ile silme arasinda baglanan agentlar etkilenmez).
function Get-FpEndpointStatus {
    $sql = @'
SET NOCOUNT ON;
IF OBJECT_ID('PA_DYNAMIC_STATUS','U') IS NULL OR OBJECT_ID('PA_DYNAMIC_STATUS_PROPS','U') IS NULL
BEGIN
    SELECT 'ERROR|PA_DYNAMIC_STATUS / PA_DYNAMIC_STATUS_PROPS tablolari bulunamadi.';
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
                     @{ L = 'Gün'; E = { $_.DaysAgo }; A = 'Right' },
                     @{ L = 'Sync'; E = { if ($_.Synced -eq '1') { 'Evet' } elseif ($_.Synced -eq '0') { 'Hayır' } else { '' } } },
                     @{ L = 'Kullanıcı'; E = { $_.LoggedInUsers } },
                     @{ L = 'Versiyon'; E = { $_.Version } } -AutoSize | Out-Host
}

# ------------------------------------------------------------------------------------
# 1) Baglanti bilgileri
# ------------------------------------------------------------------------------------
Write-Section -Title 'FORCEPOINT DLP - ENDPOINT STATUS TEMİZLİĞİ'

if ([string]::IsNullOrWhiteSpace($SqlServerInstance)) {
    $SqlServerInstance = Read-Host -Prompt 'SQL Server adı (örnek: SUNUCUADI veya SUNUCUADI\INSTANCE)'
}
if (-not $PSBoundParameters.ContainsKey('SqlAuthMode')) {
    Write-Host ''
    Write-Host 'Kimlik doğrulama türü seçin:'
    Write-Host '  1 = Windows kimlik doğrulama (varsayılan, mevcut oturumla bağlanır)'
    Write-Host '  2 = SQL Server kimlik doğrulama (kullanıcı adı/parola)'
    $authChoice = Read-Host -Prompt 'Seçiminiz [1]'
    if ($authChoice.Trim() -eq '2') { $SqlAuthMode = 'SqlLogin' }
}
if ($SqlAuthMode -eq 'SqlLogin' -and [string]::IsNullOrWhiteSpace($SqlUserName)) {
    $SqlUserName = Read-Host -Prompt 'SQL Server kullanıcı adı'
}

# ------------------------------------------------------------------------------------
# 2) Endpoint Status oku + ozet
# ------------------------------------------------------------------------------------
try {
    $endpoints = Get-FpEndpointStatus
}
catch {
    Write-Host "SQL Server bağlantısı / sorgu BAŞARISIZ: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "SQL Server bağlantısı: BAŞARILI ($SqlServerInstance / $SqlDatabaseName)" -ForegroundColor Green

Write-Section -Title 'AGENT ÖZETİ'
Write-Host ("Sistemdeki toplam agent sayısı  : {0}" -f @($endpoints).Count) -ForegroundColor White
$staleByThreshold = @{}
foreach ($t in $script:Thresholds) {
    $staleByThreshold[$t] = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $t })
    $color = if ($staleByThreshold[$t].Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("{0,2} gün ve üzeri erişmeyen agent : {1}" -f $t, $staleByThreshold[$t].Count) -ForegroundColor $color
}
Write-Host '(Sayılar birikimlidir: 7 gün ve üzeri = 7-14 + 15-29 + 30+ gün listelerinin toplamı.)' -ForegroundColor DarkGray
$noDate = @($endpoints | Where-Object { $null -eq $_.DaysAgo })
if ($noDate.Count -gt 0) {
    Write-Host ("Last Update bilgisi olmayan     : {0} (silme kapsamına alınmaz)" -f $noDate.Count) -ForegroundColor DarkYellow
}

# Listeler: her host yalnizca bir kez, ait oldugu en yuksek esik altinda gosterilir
# (30+ gun, 15-29 gun, 7-14 gun). Ozet sayilar yukarida kumulatiftir.
$bands = @(
    @{ Title = '30 GÜN VE ÜZERİ ERİŞMEYEN AGENTLAR'; Min = 30; Max = [int]::MaxValue },
    @{ Title = '15 - 29 GÜNDÜR ERİŞMEYEN AGENTLAR'; Min = 15; Max = 29 },
    @{ Title = '7 - 14 GÜNDÜR ERİŞMEYEN AGENTLAR'; Min = 7; Max = 14 }
)
foreach ($b in $bands) {
    $items = @($endpoints | Where-Object { $null -ne $_.DaysAgo -and $_.DaysAgo -ge $b.Min -and $_.DaysAgo -le $b.Max })
    Write-Section -Title "$($b.Title) ($($items.Count))"
    if ($items.Count -gt 0) { Show-EndpointTable -Items $items } else { Write-Host 'Kayıt yok.' -ForegroundColor Green }
}

if ($staleByThreshold[$script:Thresholds[0]].Count -eq 0) {
    Write-Host ''
    Write-Host "$($script:Thresholds[0]) günden eski agent yok, silinecek kayıt bulunmuyor." -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------------------------------
# 3) Esik secimi
# ------------------------------------------------------------------------------------
Write-Section -Title 'SİLME İŞLEMİ'
Write-Host 'Kaç günden eski Endpoint Status makinelerini silmek istersiniz?'
for ($i = 0; $i -lt $script:Thresholds.Count; $i++) {
    $t = $script:Thresholds[$i]
    Write-Host ("  {0} = {1} günden eski agentlar ({2} adet)" -f ($i + 1), $t, $staleByThreshold[$t].Count)
}
Write-Host '  0 = Vazgeç (hiçbir şey silinmez)'
$choice = (Read-Host -Prompt 'Seçiminiz').Trim()
if ($choice -notmatch '^[1-3]$') {
    Write-Host 'İşlem iptal edildi, hiçbir kayıt silinmedi.' -ForegroundColor DarkYellow
    exit 0
}
$selectedDays = $script:Thresholds[[int]$choice - 1]
$toDelete = @($staleByThreshold[$selectedDays])
if ($toDelete.Count -eq 0) {
    Write-Host "$selectedDays günden eski agent yok, silinecek kayıt bulunmuyor." -ForegroundColor Green
    exit 0
}

Write-Host ''
Write-Host "$selectedDays günden eski $($toDelete.Count) agent silinecek:" -ForegroundColor Yellow
Show-EndpointTable -Items $toDelete

# ------------------------------------------------------------------------------------
# 4) Cift onay
# ------------------------------------------------------------------------------------
$confirm1 = (Read-Host -Prompt "1. ONAY: $selectedDays günden eski $($toDelete.Count) agent kaydını silmek istiyor musunuz? (E/H)").Trim()
if ($confirm1 -notin @('E', 'e', 'Evet', 'evet', 'EVET')) {
    Write-Host 'İşlem iptal edildi, hiçbir kayıt silinmedi.' -ForegroundColor DarkYellow
    exit 0
}
Write-Host ''
Write-Host 'DİKKAT: Bu işlem geri alınamaz (masaüstüne CSV yedek alınacak).' -ForegroundColor Red
$confirm2 = (Read-Host -Prompt "2. ONAY: İkinci kez sileceğim, onaylıyor musunuz? Onaylamak için silinecek kayıt sayısını ($($toDelete.Count)) yazın").Trim()
if ($confirm2 -ne [string]$toDelete.Count) {
    Write-Host 'İkinci onay eşleşmedi. İşlem iptal edildi, hiçbir kayıt silinmedi.' -ForegroundColor DarkYellow
    exit 0
}

# ------------------------------------------------------------------------------------
# 5) Yedek + silme
# ------------------------------------------------------------------------------------
$desktop = [Environment]::GetFolderPath('Desktop')
$backupFile = Join-Path $desktop ("Forcepoint_EndpointStatus_Silinen_{0}gun_{1}.csv" -f $selectedDays, (Get-Date -Format 'yyyyMMdd_HHmmss'))
$toDelete | Select-Object Id, Hostname, IpAddress, LastUpdate, DaysAgo, Synced, LoggedInUsers, Version |
    Export-Csv -LiteralPath $backupFile -NoTypeInformation -Encoding UTF8
Write-Host "Yedek alındı: $backupFile" -ForegroundColor Cyan

# ID'ler guvenli: yalnizca [long] degerler SQL'e yazilir.
$idValues = ($toDelete | ForEach-Object { "($([long]$_.Id))" }) -join ",`r`n"
$deleteSql = @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @ids TABLE (ID BIGINT PRIMARY KEY);
INSERT INTO @ids (ID) VALUES
$idValues;

-- Guvenlik: secilen esikten daha YENI guncellenmis (arada yeniden baglanmis) kayitlar silinmez.
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
    Write-Host "Silme işlemi BAŞARISIZ, transaction geri alındı: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$resultLine = @($out | Where-Object { $_ -like 'RESULT|*' }) | Select-Object -First 1
if (-not $resultLine) {
    Write-Host "Silme sonucu okunamadı. Çıktı: $($out -join ' | ')" -ForegroundColor Red
    exit 1
}
$r = $resultLine -split '\|'
$deletedCount = [int]$r[1]

Write-Section -Title 'SONUÇ'
Write-Host "Silinen agent sayısı : $deletedCount" -ForegroundColor Green
Write-Host "Silinen özellik satırı (PA_DYNAMIC_STATUS_PROPS): $($r[2])" -ForegroundColor DarkGray
if ($deletedCount -lt $toDelete.Count) {
    Write-Host "$($toDelete.Count - $deletedCount) kayıt silinmedi (listeleme ile silme arasında yeniden bağlanmış veya zaten silinmiş)." -ForegroundColor DarkYellow
}
Write-Host "Kalan agent sayısı   : $(@($endpoints).Count - $deletedCount)" -ForegroundColor White
Write-Host "Yedek dosyası        : $backupFile" -ForegroundColor Cyan
