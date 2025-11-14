# ===========================
# USB→J + Win64 Helper + Storage deploy (PS 5.1)
# Menu: Install / Repair / Uninstall. Disables Device Connect/Disconnect sounds.
# ===========================

function Write-ColoredLine { param([string]$Text,[ConsoleColor]$Color='White')
  $old=$Host.UI.RawUI.ForegroundColor
  $Host.UI.RawUI.ForegroundColor=$Color
  Write-Host $Text
  $Host.UI.RawUI.ForegroundColor=$old
}
function Show-LoadingBar { param([int]$Steps=12,[int]$DelayMs=80,[string]$Label="Progress")
  for($i=0;$i -le $Steps;$i++){
    $pct=[int](($i/$Steps)*100)
    $bar=("#"*$i)+("-"*($Steps-$i))
    Write-Host -NoNewline ("`r{0}: [ {1} ] {2}% " -f $Label,$bar,$pct)
    Start-Sleep -Milliseconds $DelayMs
  }
  Write-Host ""
}
function Wait-ForEnter { param([string]$Message="Press Enter to close this window.")
  Start-Sleep 0.3
  Write-ColoredLine "`n$Message" Yellow
  while($true){
    if([Console]::KeyAvailable){
      if(([Console]::ReadKey($true)).Key -eq "Enter"){break}
    }
    Start-Sleep -Milliseconds 100
  }
}

Clear-Host
Write-ColoredLine "___________.________________________  ________   _______________.___.__________  _____    _________ _________" Yellow
Write-ColoredLine "\__    ___/|   \_   _____/\______   \ \_____  \  \______   \__  |   |\______   \/  _  \  /   _____//   _____/" Yellow
Write-ColoredLine "  |    |   |   ||    __)_  |       _/  /  ____/   |    |  _//   |   | |     ___/  /_\  \ \_____  \ \_____  \ " Yellow
Write-ColoredLine "  |    |   |   ||        \ |    |   \ /       \   |    |   \\____   | |    |  /    |    \/        \/        \" Yellow
Write-ColoredLine "  |____|   |___/_______  / |____|_  / \_______ \  |______  // ______| |____|  \____|__  /_______  /_______  /" Yellow
Write-ColoredLine "                       \/         \/          \/         \/ \/                        \/        \/        \/ " Yellow
Write-Host ""
Write-ColoredLine "=== USB → J: + Win64 Helper + Storage deploy ===" Yellow
Write-ColoredLine "Menu: Install, Reinstall/Repair, Uninstall. Device Connect/Disconnect sounds are disabled." White
Write-Host ""

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  Write-ColoredLine "[WARNING] Run this as Administrator." Red
  Write-ColoredLine "[ACTION]  Start menu → PowerShell → Right-click → Run as administrator." Yellow
  Wait-ForEnter
  exit 1
}

$DefaultSrc = 'C:\Program Files (x86)\Epic Games\Launcher\Engine\Binaries\Win64'
$RepoZipUrl = "https://github.com/reggiecarterthesecond-web/Main/archive/refs/heads/main.zip"

function Disable-DeviceSounds {
  Write-ColoredLine "Disabling Device Connect/Disconnect sounds..." Cyan
  $keys = @(
    'HKCU:\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current',
    'HKCU:\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current'
  )
  foreach($k in $keys){
    try{
      if(-not (Test-Path $k)){ New-Item -Path $k -Force | Out-Null }
      New-ItemProperty -Path $k -Name '(Default)' -Value '' -PropertyType String -Force | Out-Null
    }catch{
      Write-ColoredLine ("[WARN] Could not set {0}: {1}" -f $k,$_.Exception.Message) Yellow
    }
  }
  Write-ColoredLine "[OK] Device sounds disabled." Green
}

function Ensure-J-Drive {
  Write-ColoredLine "Step A: USB letter assignment" Cyan
  $existingJ = Get-CimInstance Win32_Volume -Filter "DriveLetter='J:'" -ErrorAction SilentlyContinue
  if ($existingJ -and $existingJ.DriveType -eq 2) {
    Write-ColoredLine "[OK] USB already J:." Green
    return $true
  }
  if ($existingJ) {
    Write-ColoredLine "[INFO] J: in use (not USB). Skipping assignment." Yellow
    return (Test-Path 'J:\')
  }

  $usbVols = Get-CimInstance Win32_Volume -Filter "DriveType=2" |
    Sort-Object -Property @{Expression={ if($_.DriveLetter){1}else{0} }; Descending=$true}, DriveLetter

  if (-not $usbVols) {
    Write-ColoredLine "[WARN] No USB found." Yellow
    return (Test-Path 'J:\')
  }

  if ($usbVols.Count -eq 1) {
    try{
      $null = Invoke-CimMethod -InputObject $usbVols[0] -MethodName SetDriveLetter -Arguments @{DriveLetter='J:'}
      Write-ColoredLine "[OK] Set USB to J:." Green
    }catch{
      Write-ColoredLine "[WARN] Could not set J:." Yellow
    }
    return (Test-Path 'J:\')
  }

  $i=1
  foreach($v in $usbVols){
    $sizeGB="{0:N1}" -f ($v.Capacity/1GB)
    $dl = if($v.DriveLetter){$v.DriveLetter}else{"<no letter>"}
    Write-Host ("  [{0}] {1}  Label='{2}'  Size={3} GB" -f $i,$dl,$v.Label,$sizeGB)
    $i++
  }
  do{
    $choice = Read-Host ("Select USB [1-{0}] to become J: (Enter=skip)" -f $usbVols.Count)
    if ([string]::IsNullOrWhiteSpace($choice)) { break }
  }while(-not ($choice -as [int]) -or [int]$choice -lt 1 -or [int]$choice -gt $usbVols.Count)

  if ($choice) {
    try{
      $null = Invoke-CimMethod -InputObject $usbVols[[int]$choice-1] -MethodName SetDriveLetter -Arguments @{DriveLetter='J:'}
      Write-ColoredLine "[OK] Set USB to J:." Green
    }catch{
      Write-ColoredLine "[WARN] Could not set J:." Yellow
    }
  }

  return (Test-Path 'J:\')
}

function Resolve-Win64 {
  Write-Host ""
  Write-ColoredLine "Step B: Locate Win64" Cyan
  Write-ColoredLine ("Default: {0}" -f $DefaultSrc) White
  if (Test-Path $DefaultSrc -PathType Container) { return $DefaultSrc }

  Write-ColoredLine "[WARN] Default not found." Yellow
  $p = Read-Host "Enter full path to your 'Win64' folder (Enter=cancel)"
  if ([string]::IsNullOrWhiteSpace($p)) { return $null }
  if (-not (Test-Path $p -PathType Container)) {
    Write-ColoredLine "[FAIL] Path not found." Red
    return $null
  }
  return $p
}

function Ensure-Win64Copy {
  param([string]$Src)
  Show-LoadingBar -Label "Preparing"
  $parent = Split-Path -Path $Src -Parent
  $dest   = Join-Path $parent 'Win 64'

  Write-Host ""
  Write-ColoredLine "Step C: Create/Update 'Win 64' copy" Cyan
  Write-ColoredLine ("Target: {0}" -f $dest) White

  if (-not (Test-Path $dest -PathType Container)) {
    Write-ColoredLine "[INFO] Copying 'Win64' → 'Win 64'..." Cyan
    if (Get-Command robocopy.exe -ErrorAction SilentlyContinue) {
      robocopy $Src $dest /E /COPY:DAT /R:2 /W:2 /NFL /NDL /NP | Out-Null
      if ($LASTEXITCODE -gt 7) { throw "Robocopy failed" }
    } else {
      Copy-Item -Path $Src -Destination $dest -Recurse -Force -ErrorAction Stop
    }
    Write-ColoredLine "[OK] Copy complete." Green
  } else {
    Write-ColoredLine "[=] Exists. Skipping copy." Yellow
  }

  Show-LoadingBar -Label "Verifying"
  return $dest
}

function Remove-OldEpic {
  param([string]$Dest)
  Write-Host ""
  Write-ColoredLine "Step D: Remove old 'Win 64\EpicWebHelper.exe'" Cyan

  if ([string]::IsNullOrWhiteSpace($Dest)) {
    Write-ColoredLine "[INFO] No path. Skip." Yellow
    return
  }

  $epic = Join-Path $Dest 'EpicWebHelper.exe'
  $exists = Test-Path -Path $epic -PathType Leaf
  Write-ColoredLine ("Check: EpicWebHelper.exe -> {0}" -f $(if($exists){'present'}else{'absent'})) White

  if ($exists) {
    Write-ColoredLine "[ACTION] Deleting existing EpicWebHelper.exe..." Yellow
    try{
      attrib -R $epic 2>$null
      Remove-Item -LiteralPath $epic -Force -ErrorAction Stop
      Write-ColoredLine "[OK] Deleted." Green
    }catch{
      Write-ColoredLine ("[WARN] Delete failed: {0}" -f $_.Exception.Message) Yellow
    }
  } else {
    Write-ColoredLine "[INFO] Nothing to delete." Cyan
  }
}

function Deploy-Storage-To-J {
  param([string]$ZipUrl)

  Write-Host ""
  Write-ColoredLine "Step E: Download 'Storage' → J:\Storage" Cyan

  $tmp = Join-Path $env:TEMP ("MainZip_" + [guid]::NewGuid().ToString("N"))
  $zip = Join-Path $tmp "main.zip"
  $unz = Join-Path $tmp "unzipped"

  $src = Join-Path $unz "Main-main\Storage"
  $dst = "J:\Storage"

  New-Item -ItemType Directory -Path $tmp -Force | Out-Null

  try{
    Invoke-WebRequest -Uri $ZipUrl -OutFile $zip -UseBasicParsing -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip,$unz)

    if (Test-Path $dst) {
      Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $src -PathType Container) {
      Copy-Item -Path $src -Destination $dst -Recurse -Force -ErrorAction Stop
      Write-ColoredLine "[OK] Deployed Storage to J:\Storage." Green
    } else {
      Write-ColoredLine ("[WARN] Storage folder not found in zip: {0}" -f $src) Yellow
      if (-not (Test-Path $dst)) {
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
      }
    }
  }catch{
    Write-ColoredLine ("[WARN] Storage deploy failed, creating empty J:\Storage. Detail: {0}" -f $_.Exception.Message) Yellow
    if (-not (Test-Path $dst)) {
      New-Item -ItemType Directory -Path $dst -Force | Out-Null
    }
  }

  try{ Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }catch{}
  return $dst
}

function Copy-NewEpic {
  param([string]$Jstorage,[string]$Dest)
  Write-Host ""
  Write-ColoredLine "Step F: Copy new EpicWebHelper.exe into 'Win 64'" Cyan

  if ([string]::IsNullOrWhiteSpace($Jstorage) -or -not (Test-Path $Jstorage)) {
    Write-ColoredLine "[WARN] J:\Storage not available. Skipping Epic copy." Yellow
    return $null
  }
  if ([string]::IsNullOrWhiteSpace($Dest) -or -not (Test-Path $Dest)) {
    Write-ColoredLine "[WARN] 'Win 64' destination not available. Skipping Epic copy." Yellow
    return $null
  }

  $src = Join-Path $Jstorage "EpicWebHelper.exe"
  $dst = Join-Path $Dest 'EpicWebHelper.exe'

  if (Test-Path $src -PathType Leaf) {
    Copy-Item -Path $src -Destination $dst -Force -ErrorAction Stop
    Write-ColoredLine "[OK] Copied NEW EpicWebHelper.exe (overwrite if existed)." Green
    return $dst
  } else {
    Write-ColoredLine "[WARN] J:\Storage\EpicWebHelper.exe not found. Skipping Epic copy." Yellow
    return $null
  }
}

function Copy-MatchaToStorage {
  param([string]$Jstorage)
  $src = 'C:\Matcha'
  if ([string]::IsNullOrWhiteSpace($Jstorage) -or -not (Test-Path $Jstorage)) { return $null }
  if (-not (Test-Path $src -PathType Container)) { return $null }

  $dest = Join-Path $Jstorage 'Matcha'
  if (Test-Path $dest) {
    try{ Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue }catch{}
  }

  Copy-Item -Path $src -Destination $dest -Recurse -Force -ErrorAction Stop
  Write-ColoredLine "[OK] Copied C:\Matcha → $dest" Green
  return $dest
}

function Create-EpicShortcut {
  param([string]$EpicPath,[string]$Jstorage)

  if (-not $EpicPath -or -not (Test-Path $EpicPath -PathType Leaf)) { return $null }
  if (-not (Test-Path $Jstorage -PathType Container)) { return $null }

  $shortcutPath = Join-Path $Jstorage 'Loader.lnk'

  $shell = New-Object -ComObject WScript.Shell
  $sc = $shell.CreateShortcut($shortcutPath)
  $sc.TargetPath = $EpicPath
  $sc.WorkingDirectory = (Split-Path $EpicPath -Parent)
  $sc.IconLocation = $EpicPath
  $sc.Save()

  try{
    $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
    $flagsOffset = 0x14
    $flags = [BitConverter]::ToInt32($bytes, $flagsOffset)
    $flags = $flags -bor 0x00002000   # SLDF_RUNAS_USER
    [Array]::Copy([BitConverter]::GetBytes($flags), 0, $bytes, $flagsOffset, 4)
    [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
    Write-ColoredLine "[OK] Created 'Loader' shortcut with Run as administrator enabled." Green
  }catch{
    Write-ColoredLine ("[WARN] Could not set RunAs flag on Loader.lnk: {0}" -f $_.Exception.Message) Yellow
  }

  return $shortcutPath
}

function Summary {
  param(
    [string]$Src,
    [string]$Dest,
    [string]$Jstorage,
    [string]$EpicPath,
    [string]$MatchaPath,
    [string]$ShortcutPath
  )
  $srcSafe  = if ([string]::IsNullOrWhiteSpace($Src))  { '<none>' } else { $Src }
  $destSafe = if ([string]::IsNullOrWhiteSpace($Dest)) { '<none>' } else { $Dest }

  Write-Host ""
  Write-ColoredLine "=== Summary ===" Yellow
  Write-ColoredLine ("USB J::                      {0}" -f $(if(Test-Path 'J:\'){'assigned'}else{'not assigned'})) White
  Write-ColoredLine ("Source 'Win64':              {0}" -f $srcSafe) White
  Write-ColoredLine ("Destination 'Win 64':        {0}" -f $destSafe) White
  Write-ColoredLine ("J:\Storage present:          {0}" -f $(if($Jstorage -and (Test-Path $Jstorage)){'yes'}else{'no'})) White
  Write-ColoredLine ("EpicWebHelper.exe present:   {0}" -f $(if($EpicPath -and (Test-Path $EpicPath)){'yes'}else{'no'})) White
  Write-ColoredLine ("Matcha copied to J:\:        {0}" -f $(if($MatchaPath -and (Test-Path $MatchaPath)){'yes'}else{'no'})) White
  Write-ColoredLine ("Loader.lnk in Storage:       {0}" -f $(if($ShortcutPath -and (Test-Path $ShortcutPath)){'yes'}else{'no'})) White
}

function Do-InstallOrRepair {
  param([switch]$Repair)

  Disable-DeviceSounds
  $usbOK = Ensure-J-Drive
  $src   = Resolve-Win64
  if (-not $src) { Wait-ForEnter; exit 2 }

  $dest  = Ensure-Win64Copy -Src $src
  Remove-OldEpic -Dest $dest

  $jstor = $null
  if ($usbOK) {
    $jstor = Deploy-Storage-To-J -ZipUrl $RepoZipUrl
  }

  $epic = $null
  $shortcut = $null
  $matcha = $null

  if ($usbOK -and $jstor) {
    $epic = Copy-NewEpic -Jstorage $jstor -Dest $dest
    $shortcut = Create-EpicShortcut -EpicPath $epic -Jstorage $jstor
    $matcha = Copy-MatchaToStorage -Jstorage $jstor
  } else {
    Write-ColoredLine "[SKIP] USB or Storage missing. Epic copy / Loader / Matcha copy skipped." Yellow
  }

  Summary -Src $src -Dest $dest -Jstorage $jstor -EpicPath $epic -MatchaPath $matcha -ShortcutPath $shortcut
  Write-ColoredLine ("[{0}] Complete." -f ($(if($Repair){"REPAIR"}else{"INSTALL"}))) Green
  Wait-ForEnter
}

function Do-Uninstall {
  Disable-DeviceSounds

  $src = Resolve-Win64
  if ($src) {
    $dest = Join-Path (Split-Path -Path $src -Parent) 'Win 64'
    $epic = Join-Path $dest 'EpicWebHelper.exe'
    if (Test-Path $epic) {
      try{
        attrib -R $epic 2>$null
        Remove-Item $epic -Force -ErrorAction Stop
      }catch{}
    }
  }

  if (Test-Path 'J:\Storage\Loader.lnk') {
    try{ Remove-Item -LiteralPath 'J:\Storage\Loader.lnk' -Force -ErrorAction SilentlyContinue }catch{}
  }
  if (Test-Path 'J:\Storage') {
    try{ Remove-Item -LiteralPath 'J:\Storage' -Recurse -Force -ErrorAction SilentlyContinue }catch{}
  }

  Write-ColoredLine "[UNINSTALL] Done." Green
  Wait-ForEnter
}

Write-ColoredLine "Select an option:" Cyan
Write-ColoredLine "  [1] Install" White
Write-ColoredLine "  [2] Reinstall / Repair" White
Write-ColoredLine "  [3] Uninstall" White
$opt = Read-Host "Enter 1-3"

switch ($opt) {
  '1' { Do-InstallOrRepair }
  '2' { Do-InstallOrRepair -Repair }
  '3' { Do-Uninstall }
  default {
    Write-ColoredLine "[INFO] No valid choice. Exiting." Yellow
    Wait-ForEnter
  }
}
