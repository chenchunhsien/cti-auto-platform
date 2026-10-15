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
#>

[CmdletBinding()]
param(
    [switch]$NoPush,          # 不執行 git push
    [switch]$Full,            # 忽略高水位線，強制回溯
    [int]$SinceHours = 0      # 搭配 -Full 自訂回溯時數
)

$ErrorActionPreference = 'Stop'

# ---- 切換至專案目錄 ----
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -Path $ProjectRoot

$LogFile = Join-Path $ProjectRoot 'sync.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    Add-Content -Path $LogFile -Value $line -Encoding utf8
}

# ---- 日誌輪替（超過 5MB 另存備份）----
if (Test-Path $LogFile) {
    $sizeMB = (Get-Item $LogFile).Length / 1MB
    if ($sizeMB -gt 5) {
        $archive = Join-Path $ProjectRoot ("sync_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Move-Item -Path $LogFile -Destination $archive -Force
    }
}

Write-Log ("=" * 60)
Write-Log "CTI 同步開始 | 專案目錄: $ProjectRoot"

# ---- 找出 Python 直譯器（優先使用專案 venv）----
$PythonExe = $null
$candidates = @(
    (Join-Path $ProjectRoot 'venv\Scripts\python.exe'),
    (Join-Path $ProjectRoot '.venv\Scripts\python.exe')
)
foreach ($c in $candidates) {
    if (Test-Path $c) { $PythonExe = $c; break }
}
if (-not $PythonExe) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { $PythonExe = $cmd.Source }
}
if (-not $PythonExe) {
    $cmd = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($cmd) { $PythonExe = $cmd.Source }
}

if (-not $PythonExe) {
    Write-Log "找不到 Python 直譯器，請先安裝 Python 或建立 venv。" 'ERROR'
    exit 1
}
Write-Log "使用直譯器: $PythonExe"

# ---- 組裝參數 ----
$pyArgs = @('pipeline.py')
if ($NoPush)        { $pyArgs += '--no-push' }
if ($Full)          { $pyArgs += '--full' }
if ($SinceHours -gt 0) { $pyArgs += @('--since-hours', $SinceHours) }

Write-Log ("執行: {0} {1}" -f $PythonExe, ($pyArgs -join ' '))

# ---- 執行並串接輸出至 log ----
$exitCode = 0
try {
    & $PythonExe @pyArgs 2>&1 | ForEach-Object {
        $text = $_.ToString()
        Write-Output $text
        Add-Content -Path $LogFile -Value $text -Encoding utf8
    }
    $exitCode = $LASTEXITCODE
}
catch {
    Write-Log "執行例外: $($_.Exception.Message)" 'ERROR'
    $exitCode = 1
}

if ($exitCode -eq 0) {
    Write-Log "CTI 同步完成 (exit=0)"
} else {
    Write-Log "CTI 同步失敗 (exit=$exitCode)，高水位線未更新，下次執行將自動補抓。" 'ERROR'
}
Write-Log ("=" * 60)

exit $exitCode
