# ===========================
# Win64Helper.ps1
# ===========================
# - Run as Administrator
# - If default Win64 missing, you can paste a custom path
# - Copies Win64 -> "Win 64" (if missing)
# - ALWAYS deletes Win 64\EpicWebHelper.exe if present
# - Colored output, stays open until Enter is pressed
# Compatible with Windows PowerShell 5.1 and PowerShell 7+

# -------------------------
# Helpers
# -------------------------
function Write-ColoredLine {
    param (
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    $old = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $old
}

function Show-LoadingBar {
    param([int]$Steps = 12, [int]$DelayMs = 80, [string]$Label = "Progress")
    for ($i = 0; $i -le $Steps; $i++) {
        $pct = [int](($i / $Steps) * 100)
        $bar = "#" * $i + "-" * ($Steps - $i)
        Write-Host -NoNewline ("`r{0}: [ {1} ] {2}% " -f $Label, $bar, $pct)
        Start-Sleep -Milliseconds $DelayMs
    }
    Write-Host ""
}

function Wait-ForEnter {
    param([string]$Message = "Press Enter to close this window.")
    Start-Sleep -Milliseconds 300
    Write-ColoredLine "`n$Message" Yellow
    while ($true) {
        if ([System.Console]::KeyAvailable) {
            $k = [System.Console]::ReadKey($true)
            if ($k.Key -eq "Enter") { break }
        }
        Start-Sleep -Milliseconds 100
    }
}

# -------------------------
# Header (ASCII art from user)
# -------------------------
Clear-Host
Write-ColoredLine "___________.________________________  ________   _______________.___.__________  _____    _________ _________" Yellow
Write-ColoredLine "\__    ___/|   \_   _____/\______   \ \_____  \  \______   \__  |   |\______   \/  _  \  /   _____//   _____/" Yellow
Write-ColoredLine "  |    |   |   ||    __)_  |       _/  /  ____/   |    |  _//   |   | |     ___/  /_\  \ \_____  \ \_____  \ " Yellow
Write-ColoredLine "  |    |   |   ||        \ |    |   \ /       \   |    |   \\____   | |    |  /    |    \/        \/        \" Yellow
Write-ColoredLine "  |____|   |___/_______  / |____|_  / \_______ \  |______  // ______| |____|  \____|__  /_______  /_______  /" Yellow
Write-ColoredLine "                       \/         \/          \/         \/ \/                        \/        \/        \/ " Yellow
Write-Host ""
Write-ColoredLine "=== Win64 Helper ===" Yellow
Write-ColoredLine "Task: Duplicate 'Win64' -> 'Win 64' and ALWAYS remove EpicWebHelper.exe in 'Win 64' if present." White
Write-ColoredLine "Note: Run this script as Administrator." White
Write-Host ""

# -------------------------
# Admin gate
# -------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-ColoredLine "[WARNING] This script is NOT running with Administrator privileges." Red
    Write-ColoredLine "[ACTION] Right-click PowerShell and select 'Run as administrator' then run again." Yellow
    Wait-ForEnter
    exit 1
}

# -------------------------
# Paths and discovery
# -------------------------
$DefaultSrc = 'C:\Program Files (x86)\Epic Games\Launcher\Engine\Binaries\Win64'

Write-ColoredLine "Step 1/3: Locate Win64" Cyan
Write-ColoredLine ("Default expected: {0}" -f $DefaultSrc) White

if (-not (Test-Path -Path $DefaultSrc -PathType Container)) {
    Write-ColoredLine "[WARN] Default Win64 path not found." Yellow
    Write-ColoredLine "If Epic Games is installed in a different drive/path paste the full folder path for 'Win64' now." White
    Write-Host ""
    $userPath = Read-Host "Enter Win64 path (or press Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        Write-ColoredLine "[FAIL] No path provided. Install/reinstall Epic Games Launcher or run again with the correct path." Red
        Wait-ForEnter
        exit 2
    }
    if (-not (Test-Path -Path $userPath -PathType Container)) {
        Write-ColoredLine "[FAIL] Provided path is invalid or not found: $userPath" Red
        Wait-ForEnter
        exit 3
    }
    $Src = $userPath
} else {
    $Src = $DefaultSrc
}

Write-ColoredLine ("[OK] Using Win64 source: {0}" -f $Src) Green
Show-LoadingBar -Label "Preparing"

# compute dest and target exe
$Parent = Split-Path -Path $Src -Parent
$Dest   = Join-Path $Parent 'Win 64'
$Epic   = Join-Path $Dest 'EpicWebHelper.exe'

# -------------------------
# Copy step
# -------------------------
Write-Host ""
Write-ColoredLine "Step 2/3: Create/Update 'Win 64' copy" Cyan
Write-ColoredLine ("Target: {0}" -f $Dest) White

if (-not (Test-Path -Path $Dest -PathType Container)) {
    Write-ColoredLine "[INFO] Copying 'Win64' -> 'Win 64' using robocopy..." Cyan
    # Use robocopy for reliability. If not available, fallback to Copy-Item.
    if (Get-Command robocopy.exe -ErrorAction SilentlyContinue) {
        robocopy $Src $Dest /E /COPY:DAT /R:2 /W:2 /NFL /NDL /NP | Out-Null
        $rc = $LASTEXITCODE
        if ($rc -gt 7) {
            Write-ColoredLine ("[FAIL] Robocopy failed with exit code {0}" -f $rc) Red
            Write-ColoredLine "Close Epic processes or retry after reboot." Yellow
            Wait-ForEnter
            exit 4
        }
    } else {
        try {
            Copy-Item -Path $Src -Destination $Dest -Recurse -Force -ErrorAction Stop
        } catch {
            Write-ColoredLine ("[FAIL] Copy-Item failed: {0}" -f $_.Exception.Message) Red
            Wait-ForEnter
            exit 5
        }
    }
    Write-ColoredLine "[OK] Copy complete." Green
} else {
    Write-ColoredLine "[=] 'Win 64' already exists. Skipping copy." Yellow
}
Show-LoadingBar -Label "Verifying"

# -------------------------
# Delete EpicWebHelper.exe (unconditional)
# -------------------------
Write-Host ""
Write-ColoredLine "Step 3/3: Remove EpicWebHelper.exe in 'Win 64' (unconditional)" Cyan

$epicExists = Test-Path -Path $Epic -PathType Leaf
Write-ColoredLine ("Check: EpicWebHelper.exe -> {0}" -f $(if($epicExists){'present'}else{'absent'})) White

if ($epicExists) {
    Write-ColoredLine "[ACTION] Deleting EpicWebHelper.exe..." Yellow
    try {
        # clear read-only attribute if present
        attrib -R $Epic 2>$null
        Remove-Item -LiteralPath $Epic -Force -ErrorAction Stop
        Write-ColoredLine "[OK] EpicWebHelper.exe deleted." Green
    } catch {
        Write-ColoredLine ("[FAIL] Delete failed: {0}" -f $_.Exception.Message) Red
        Write-ColoredLine "Close Epic/EpicWebHelper processes, ensure admin rights, retry later." Yellow
        Wait-ForEnter
        exit 6
    }
} else {
    Write-ColoredLine "[INFO] EpicWebHelper.exe not present. Nothing to delete." Cyan
}

# -------------------------
# Summary and finish
# -------------------------
Write-Host ""
Write-ColoredLine "=== Summary ===" Yellow
Write-ColoredLine ("Source:      {0}" -f $Src) White
Write-ColoredLine ("Destination: {0}" -f $Dest) White
Write-ColoredLine ("EpicWebHelper.exe: {0}" -f $(if(Test-Path $Epic){'present'}else{'absent'})) White
Write-ColoredLine "[DONE] All operations completed." Green

Wait-ForEnter
