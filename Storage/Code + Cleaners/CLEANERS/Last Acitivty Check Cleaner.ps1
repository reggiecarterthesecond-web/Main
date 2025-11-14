# Nuke-LAV-Traces.ps1 — aggressive, but safe (backs up first)

# --- Elevation check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

Write-Host "Stopping LastActivityView and Explorer..." -ForegroundColor Cyan
Get-Process LastActivityView -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$bk = Join-Path $env:TEMP "LAV_Backup_$ts"
New-Item -ItemType Directory -Path $bk | Out-Null

# --- Registry branches LAV reads ---
$branches = @(
  'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags',
  'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
  'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist',
  'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
)

Write-Host "Backing up registry branches to $bk ..." -ForegroundColor Yellow
foreach ($b in $branches) { try { reg.exe export "$b" "$bk\$(($b -replace '[\\/:*?""<>|]','_')).reg" /y | Out-Null } catch {} }

Write-Host "Deleting ShellBags (Bags/BagMRU) completely..." -ForegroundColor Yellow
reg.exe delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f | Out-Null
reg.exe delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f | Out-Null

Write-Host "Clearing Explorer MRUs (Open/Save, RecentDocs, TypedPaths, RunMRU)..." -ForegroundColor Yellow
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /f | Out-Null
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /f | Out-Null
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f | Out-Null
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f | Out-Null
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f | Out-Null

Write-Host "Clearing UserAssist + MuiCache..." -ForegroundColor Yellow
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f | Out-Null
reg.exe delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /f | Out-Null

Write-Host "Wiping Jump Lists..." -ForegroundColor Yellow
$auto = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations'
$cust = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\CustomDestinations'
Get-ChildItem $auto,$cust -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# (Optional) Recent links folder
$recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
Get-ChildItem $recent -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "Restarting Explorer..." -ForegroundColor Cyan
Start-Process explorer.exe
Write-Host "`n✅ Done. Press F5 in LastActivityView." -ForegroundColor Green
Write-Host "Backups are in: $bk" -ForegroundColor DarkGray