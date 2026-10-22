<#
    run_sync.ps1
    ------------
    供 Windows 工作排程器 (Task Scheduler) 執行的 CTI 同步腳本。

    排程器設定建議：
      程式或指令碼: powershell.exe
      新增引數    : -NoProfile -ExecutionPolicy Bypass -File "D:\cti-auto-platform\run_sync.ps1"
      起始位置    : D:\cti-auto-platform

    高水位線機制會自動補抓電腦關機期間（週末/假日）漏掉的區間，
    因此排程漏跑不會造成資料缺口。

    注意：本檔必須以 UTF-8 with BOM 儲存，
          否則 Windows PowerShell 5.1 會以 ANSI 讀取而破壞中文字元。
#>

[CmdletBinding()]
param(
    [switch]$NoPush,
    [switch]$Full,
    [int]$SinceHours = 0,
    # 落後太多（例如停機數天）時，單次執行會因 pipeline.py 的 MAX_PAGES
    # 保護機制只推進一部分高水位線；這裡讓同一次排程觸發就連續補跑
    # 多輪，不必乾等到下一個排程時間點才能繼續。
    [int]$MaxCatchupRuns = 5,
    # 每輪跑完後檢查目前落後幾小時，低於這個門檻就視為已追上，停止補跑
    [double]$CatchupGapHours = 1.0
)

$ErrorActionPreference = 'Stop'

# ---- 切換至專案目錄 ----
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -Path $ProjectRoot

$LogFile = Join-Path $ProjectRoot 'sync.log'
# 帶 BOM：讓記事本與 PS 5.1 的 Get-Content 能正確判讀中文，不致亂碼
$LogEncoding = New-Object System.Text.UTF8Encoding($true)

function Write-LogLine {
    param([string]$Text)
    Write-Output $Text
    # 用 .NET 直接附加，避免 PS 5.1 Add-Content 的串流鎖定問題
    [System.IO.File]::AppendAllText($LogFile, $Text + [Environment]::NewLine, $LogEncoding)
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    Write-LogLine ("{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message)
}

# ---- 日誌輪替（超過 5MB 另存備份）----
if (Test-Path $LogFile) {
    if ((Get-Item $LogFile).Length / 1MB -gt 5) {
        $archive = Join-Path $ProjectRoot ("sync_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Move-Item -Path $LogFile -Destination $archive -Force
    }
}

Write-Log ("=" * 60)
Write-Log "CTI 同步開始 | 專案目錄: $ProjectRoot"

# ---- 防止重複執行 ----
# 手動補跑（例如落後很多、連續補跑好幾輪耗時較久）途中，若又被 Task
# Scheduler 的排程觸發（例如每天固定 09:00），兩個程序會同時搶著寫
# sync.log、甚至同時跑 pipeline.py 去動 data/ 底下的檔案與 git push，
# 實測發生過直接讓其中一個程序因檔案鎖定衝突而中途崩潰。用一個簡單的
# PID lock 檔避免同時有兩個實例在跑；lock 檔裡的程序如果已經不存在
# （例如上次異常中斷沒清乾淨），視為過期 lock，清掉後正常繼續執行。
$LockFile = Join-Path $ProjectRoot 'sync.lock'
if (Test-Path $LockFile) {
    $lockPid = (Get-Content $LockFile -Raw -ErrorAction SilentlyContinue).Trim()
    $existing = $null
    if ($lockPid) { $existing = Get-Process -Id $lockPid -ErrorAction SilentlyContinue }
    if ($existing) {
        Write-Log "偵測到另一個執行中的同步程序 (PID=$lockPid)，本次略過，避免同時寫入 data/ 或衝突 push" 'WARN'
        exit 0
    }
    Write-Log "發現過期的 lock 檔（程序已不存在），清除後繼續" 'WARN'
}
Set-Content -Path $LockFile -Value $PID -Encoding ASCII

try {

# ---- 等待網路就緒 ----
# 開機觸發（AtStartup trigger）時，Windows 判定「開機完成」的時間點常常早於
# 網卡/DNS 實際就緒（尤其是 Wi-Fi、VPN 或網域環境），導致排程一開機就跑、
# 但 Luminar API 網域還無法解析而直接失敗（曾實際發生：getaddrinfo failed）。
# 這裡在呼叫 pipeline.py 前，先輪詢確認網域可解析，最多等 3 分鐘；
# 逾時仍會照常嘗試執行，失敗時 pipeline.py 自己會記錄清楚的錯誤訊息。
function Wait-ForNetwork {
    param(
        [string]$TargetHost = 'cyberluminar.com',
        [int]$MaxWaitSeconds = 180,
        [int]$IntervalSeconds = 10
    )
    $elapsed = 0
    while ($elapsed -lt $MaxWaitSeconds) {
        try {
            [System.Net.Dns]::GetHostAddresses($TargetHost) | Out-Null
            if ($elapsed -gt 0) {
                Write-Log "網路就緒（等待 $elapsed 秒後可解析 $TargetHost）"
            }
            return
        }
        catch {
            Start-Sleep -Seconds $IntervalSeconds
            $elapsed += $IntervalSeconds
        }
    }
    Write-Log "等待 $MaxWaitSeconds 秒後仍無法解析 $TargetHost，照常繼續執行" 'WARN'
}

$LuminarHost = 'cyberluminar.com'
$envFile = Join-Path $ProjectRoot '.env'
if (Test-Path $envFile) {
    $baseUrlLine = Get-Content $envFile -Encoding UTF8 | Where-Object { $_ -match '^LUMINAR_BASE_URL=' } | Select-Object -First 1
    if ($baseUrlLine -and ($baseUrlLine -match '://([^/"\s]+)')) {
        $LuminarHost = $Matches[1]
    }
}
Wait-ForNetwork -TargetHost $LuminarHost

# ---- 找出 Python 直譯器（優先使用專案 venv）----
$PythonExe = $null
foreach ($c in @(
        (Join-Path $ProjectRoot 'venv\Scripts\python.exe'),
        (Join-Path $ProjectRoot '.venv\Scripts\python.exe'))) {
    if (Test-Path $c) { $PythonExe = $c; break }
}
if (-not $PythonExe) {
    foreach ($n in @('python.exe', 'py.exe')) {
        $cmd = Get-Command $n -ErrorAction SilentlyContinue
        if ($cmd) { $PythonExe = $cmd.Source; break }
    }
}
if (-not $PythonExe) {
    Write-Log "找不到 Python 直譯器，請先安裝 Python 或建立 venv。" 'ERROR'
    exit 1
}
Write-Log "使用直譯器: $PythonExe"

# ---- git 需在 PATH 中（自動推送用）----
if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    $gitCmd = 'C:\Program Files\Git\cmd'
    if (Test-Path $gitCmd) {
        $env:PATH = "$gitCmd;$env:PATH"
        Write-Log "已將 Git 加入本次執行的 PATH: $gitCmd"
    }
    else {
        Write-Log "PATH 中找不到 git，自動推送可能失敗。" 'WARN'
    }
}

# ---- 組裝參數 ----
$pyArgs = @('pipeline.py')
if ($NoPush) { $pyArgs += '--no-push' }
if ($Full) { $pyArgs += '--full' }
if ($SinceHours -gt 0) { $pyArgs += @('--since-hours', "$SinceHours") }

Write-Log ("執行: {0} {1}" -f $PythonExe, ($pyArgs -join ' '))

# ---- 讀取目前落後幾小時（供補跑迴圈判斷要不要繼續）----
function Get-SyncGapHours {
    $stateFile = Join-Path $ProjectRoot 'data\sync_state.json'
    if (-not (Test-Path $stateFile)) { return $null }
    try {
        $state = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $tsUtc = $state.last_successful_timestamp_utc
        if (-not $tsUtc) { return $null }
        $lastTs = [DateTimeOffset]::Parse($tsUtc, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        return ([DateTimeOffset]::UtcNow - $lastTs).TotalHours
    }
    catch {
        Write-Log "讀取 sync_state.json 失敗，無法判斷落後時數: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

# ---- 執行並串接輸出至 log（落後太多時連續補跑多輪）----
$env:PYTHONIOENCODING = 'utf-8'
$exitCode = 0

for ($run = 1; $run -le $MaxCatchupRuns; $run++) {
    if ($run -gt 1) {
        Write-Log "----- 連續補跑第 $run / $MaxCatchupRuns 輪 -----"
    }

    try {
        & $PythonExe @pyArgs 2>&1 | ForEach-Object { Write-LogLine ($_.ToString()) }
        $exitCode = $LASTEXITCODE
    }
    catch {
        Write-Log "執行例外: $($_.Exception.Message)" 'ERROR'
        $exitCode = 1
    }

    switch ($exitCode) {
        0 { Write-Log "本輪同步完成 (exit=0)" }
        3 { Write-Log "Luminar 帳號未開通該 feed (exit=3)，請洽 Luminar 支援窗口。" 'ERROR' }
        default { Write-Log "本輪同步失敗 (exit=$exitCode)，高水位線未更新，下次執行將自動補抓。" 'ERROR' }
    }

    # 失敗就整個停止，不要在錯誤狀態下一直重試（例如憑證錯誤、網路不通）
    if ($exitCode -ne 0) { break }

    $gapHours = Get-SyncGapHours
    if ($null -eq $gapHours) {
        Write-Log "無法判斷目前落後時數，不再繼續補跑" 'WARN'
        break
    }
    Write-Log ("目前落後 {0:N1} 小時" -f $gapHours)
    if ($gapHours -lt $CatchupGapHours) {
        if ($run -gt 1) { Write-Log "已追上進度，結束連續補跑" }
        break
    }
    if ($run -eq $MaxCatchupRuns) {
        Write-Log "已達單次排程最多補跑 $MaxCatchupRuns 輪，剩餘落後留待下次排程繼續補抓" 'WARN'
    }
}

Write-Log "CTI 同步結束 (exit=$exitCode)"
Write-Log ("=" * 60)

}
finally {
    Remove-Item -Path $LockFile -Force -ErrorAction SilentlyContinue
}

exit $exitCode
