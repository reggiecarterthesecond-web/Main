# Run as Administrator check
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Restarting as Administrator..."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$keywords = @(
    'matcha','evolve','mooze','isabelle','matrix','tsar','melatonin','serotonin',
    'aimmy','aimbot','valex','vector','photon','nezur','yebra','haze/myst','haze','myst',
    'horizon','havoc','colorbot','xeno','solara','olduimatrix','monkeyaim',
    'thunderaim','thunderclient','celex','zarora','juju','nezure','fluxus','clumsy',
    'matcha\.exe','triggerbot\.exe','aimmy\.exe','mystw\.exe','thing\.exe','dx9ware\.exe',
    'fusionhacks\.zip','release\.zip','build\.zip','build\.rar','bootstrappernew',
    'santoware','bootstrappernew\.exe','xeno\.exe','xenoui\.exe','solara\.exe',
    'mapper\.exe','evolve\.exe','boostrapper\.exe','mathshard','clean\.exe',
    'boostrappernew\.exe','authenticator\.exe','thing\.exe','app.exe','update.exe','updater.exe','upgrade','threat-','cleaner',
    "J:","A:","B:","D:","E:","F:","G:","H:","I:","J:","K:","L:","M:",
    "N:","O:","P:","Q:","R:","S:","T:","U:","V:","W:","X:","Y:","Z:",
    "Aura","loader","MainRunner","usermode"
)

$keywords = $keywords | ForEach-Object { $_.ToLower() }

function Contains-Keyword {
    param ([string]$text)
    
    if ([string]::IsNullOrEmpty($text)) {
        return $false
    }
    
    $lowerText = $text.ToLower()
    foreach ($keyword in $keywords) {
        # More flexible matching for file paths and registry values
        if ($lowerText -match [regex]::Escape($keyword) -or 
            $lowerText -match "\\$keyword\\" -or 
            $lowerText -match "\\$keyword\.exe" -or 
            $lowerText -eq $keyword) {
            return $true
        }
    }
    return $false
}

function Should-Delete-RegistryValue {
    param ([string]$value)
    
    if ([string]::IsNullOrEmpty($value)) {
        return $false
    }
    
    $lowerValue = $value.ToLower()
    
    foreach ($keyword in $keywords) {
        # More comprehensive matching for registry values
        if ($lowerValue -match [regex]::Escape($keyword) -or 
            $lowerValue -match ".*\\$keyword\\.*" -or 
            $lowerValue -match ".*\\$keyword\.exe.*" -or
            $lowerValue -match ".*$keyword.*") {
            return $true
        }
    }
    return $false
}

function Is-NonC-Drive-Path {
    param ([string]$path)
    
    if ([string]::IsNullOrEmpty($path)) {
        return $false
    }
    
    # Check if path starts with a drive letter other than C:
    if ($path -match '^[A-BD-Z]:\\') {
        return $true
    }
    
    # Check for USB drive patterns (common removable drives)
    if ($path -match '\\\\\?\\[A-BD-Z]:' -or $path -match '^[A-BD-Z]:\\') {
        return $true
    }
    
    return $false
}

function Get-ShortcutTarget {
    param ([string]$shortcutPath)
    
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        return $shortcut.TargetPath
    } catch {
        return $null
    }
}

Write-Host "Starting comprehensive cleanup..." -ForegroundColor Green

# Get current user SID more reliably
$currentUserSID = (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$env:USERNAME" }).SID
if (-not $currentUserSID) {
    $currentUserSID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "*$env:USERNAME*"}).PSChildName
}

Write-Host "User SID: $currentUserSID" -ForegroundColor Yellow

$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\ApplicationAssociationStore",
    "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated"
)

if ($currentUserSID) {
    $registryPaths += @(
        "Registry::HKEY_USERS\$currentUserSID\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\Shell\Associations\ApplicationAssociationStore",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
    )
}

$totalRemoved = 0
foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            Write-Host "`nProcessing registry path: $path" -ForegroundColor Cyan
            
            # Process main key properties
            $mainKeyProperties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($mainKeyProperties) {
                $propertyNames = $mainKeyProperties.PSObject.Properties | Where-Object { 
                    $_.MemberType -eq 'NoteProperty' -and $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
                } | Select-Object -ExpandProperty Name
                
                foreach ($propName in $propertyNames) {
                    $propValue = $mainKeyProperties.$propName
                    
                    if (($propValue -is [string] -and (Should-Delete-RegistryValue $propValue)) -or 
                        (Contains-Keyword $propName)) {
                        try {
                            Remove-ItemProperty -Path $path -Name $propName -Force -ErrorAction SilentlyContinue
                            Write-Host "✓ Removed registry value: $propName" -ForegroundColor Green
                            $totalRemoved++
                        } catch {
                            Write-Host "✗ Failed to remove value $propName from $path : $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }
            
            # Process subkeys recursively
            $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Recurse
            
            foreach ($item in $items) {
                try {
                    $subKeyPath = $item.PSPath
                    $subKeyProperties = Get-ItemProperty -Path $subKeyPath -ErrorAction SilentlyContinue
                    
                    if ($subKeyProperties) {
                        $propertyNames = $subKeyProperties.PSObject.Properties | Where-Object { 
                            $_.MemberType -eq 'NoteProperty' -and $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
                        } | Select-Object -ExpandProperty Name
                        
                        $deleteEntireKey = $false
                        
                        foreach ($propName in $propertyNames) {
                            $propValue = $subKeyProperties.$propName
                            
                            if (($propValue -is [string] -and (Should-Delete-RegistryValue $propValue)) -or 
                                (Contains-Keyword $propName)) {
                                try {
                                    Remove-ItemProperty -Path $subKeyPath -Name $propName -Force -ErrorAction SilentlyContinue
                                    Write-Host "✓ Removed registry value: $subKeyPath\$propName" -ForegroundColor Green
                                    $deleteEntireKey = $true
                                    $totalRemoved++
                                } catch {
                                    Write-Host "✗ Failed to remove value $propName from $subKeyPath : $($_.Exception.Message)" -ForegroundColor Red
                                }
                            }
                        }
                        
                        # Check if the key name itself contains keywords
                        if (Contains-Keyword $subKeyPath) {
                            $deleteEntireKey = $true
                        }
                        
                        if ($deleteEntireKey) {
                            try {
                                Remove-Item -Path $subKeyPath -Recurse -Force -ErrorAction SilentlyContinue
                                Write-Host "✓ Removed registry key: $subKeyPath" -ForegroundColor Green
                                $totalRemoved++
                            } catch {
                                Write-Host "✗ Failed to remove key $subKeyPath : $($_.Exception.Message)" -ForegroundColor Red
                            }
                        }
                    }
                } catch {
                    Write-Host "Error processing subkey: $($_.Exception.Message)" -ForegroundColor Red
                    continue
                }
            }
        }
    } catch {
        Write-Host "Error processing path $path : $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
}

Write-Host "`nRegistry cleanup completed. Total items removed: $totalRemoved" -ForegroundColor Yellow

# TARGETED Prefetch cleanup - ONLY deletes files matching keywords
Write-Host "`nStarting TARGETED Prefetch cleanup (keywords only)..." -ForegroundColor Cyan
$prefetchCount = 0

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "Scanning Prefetch directory: $prefetchPath" -ForegroundColor Yellow
    
    # ONLY delete files that match keywords
    Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fileName = $_.Name.ToLower()
        $fileDeleted = $false
        
        foreach ($keyword in $keywords) {
            $cleanKeyword = $keyword.Replace('.exe', '').Replace('\.exe', '').Replace('.', '')
            # Match the keyword in the filename
            if ($fileName -match [regex]::Escape($cleanKeyword)) {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed targeted prefetch file: $($_.Name)" -ForegroundColor Green
                    $prefetchCount++
                    $fileDeleted = $true
                    break
                } catch {
                    Write-Host "✗ Failed to remove targeted prefetch file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        
        # Also check for common cheat patterns in prefetch
        if (-not $fileDeleted) {
            $suspiciousPatterns = @(
                'matcha', 'evolve', 'aimmy', 'myst', 'haze', 'xeno', 'solara', 
                'thing', 'triggerbot', 'dx9ware', 'bootstrapper', 'authenticator', 
                'mainrunner', 'aimbot', 'usermode'
            )
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($fileName -match $pattern) {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "✓ Removed suspicious prefetch file: $($_.Name)" -ForegroundColor Green
                        $prefetchCount++
                        break
                    } catch {
                        Write-Host "✗ Failed to remove suspicious prefetch file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    }
    
    if ($prefetchCount -eq 0) {
        Write-Host "No prefetch files matching keywords were found." -ForegroundColor Yellow
    } else {
        Write-Host "Targeted Prefetch cleanup completed. Files removed: $prefetchCount" -ForegroundColor Yellow
    }
} else {
    Write-Host "Prefetch path not found: $prefetchPath" -ForegroundColor Red
}

# Enhanced Recent files cleanup with C++, AHK, USB detection AND keyword targeting
Write-Host "`nStarting Enhanced Recent files cleanup (C++, AHK, USB content, Keywords)..." -ForegroundColor Cyan
$recentCount = 0

$recentRoot  = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
$autoDest    = Join-Path $recentRoot 'AutomaticDestinations'
$customDest  = Join-Path $recentRoot 'CustomDestinations'

# Clean main recent folder by filename patterns
Write-Host "Scanning main Recent folder for keyword matches..." -ForegroundColor Yellow
Get-ChildItem -Path $recentRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object { 
    $_.Name -like "*MainRunner*" -or (Contains-Keyword $_.Name)
} | ForEach-Object {
    try {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Removed recent file (keyword match): $($_.Name)" -ForegroundColor Green
        $recentCount++
    } catch {
        Write-Host "✗ Failed to remove recent file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Clean automatic and custom destinations by content patterns
foreach ($folder in @($autoDest, $customDest)) {
    if (Test-Path $folder) {
        Write-Host "Scanning destination folder for content matches: $folder" -ForegroundColor Yellow
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            try {
                # Check file content for keywords
                $contentMatch = $false
                $matchedKeyword = ""
                
                foreach ($keyword in @('MainRunner', 'aimbot', 'usermode') + $keywords) {
                    if (Select-String -Path $file.FullName -Pattern $keyword -SimpleMatch -Quiet -ErrorAction SilentlyContinue) {
                        $contentMatch = $true
                        $matchedKeyword = $keyword
                        break
                    }
                }
                
                if ($contentMatch) {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed destination file (content match: $matchedKeyword): $($file.Name)" -ForegroundColor Green
                    $recentCount++
                }
            } catch {
                Write-Host "✗ Error processing destination file $($file.Name) : $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# Additional enhanced recent file checks for C++, AHK, and USB content
Write-Host "`nPerforming enhanced file type and location checks..." -ForegroundColor Yellow
$recentPaths = @($recentRoot, $autoDest, $customDest)

foreach ($recentPath in $recentPaths) {
    if (Test-Path $recentPath) {
        Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            $name = $file.Name.ToLower()
            $delete = $false

            # Check for suspicious filenames
            if ($name -match 'thing' -or $name -match 'storage') {
                $delete = $true
            }

            # Check for C++ files (.cpp)
            if ($file.Extension -eq '.cpp' -or $name -match '\.cpp$') {
                $delete = $true
                Write-Host "✓ Found C++ file in recent: $($file.Name)" -ForegroundColor Yellow
            }

            # Check for AHK files
            if ($file.Extension -eq '.ahk' -or $name -match '\.ahk$') {
                $delete = $true
                Write-Host "✓ Found AHK file in recent: $($file.Name)" -ForegroundColor Yellow
            }

            # Check shortcuts for USB content and AHK targets
            if ($file.Extension -eq '.lnk') {
                try {
                    $targetPath = (Get-ShortcutTarget $file.FullName)
                    
                    if ($targetPath) {
                        # Check if shortcut target is on non-C drive (USB)
                        if (Is-NonC-Drive-Path $targetPath) {
                            $delete = $true
                            Write-Host "✓ Found USB shortcut target: $targetPath" -ForegroundColor Yellow
                        }
                        
                        # Check if shortcut target is AHK file
                        if ($targetPath -match '\.ahk$') {
                            $delete = $true
                            Write-Host "✓ Found AHK shortcut target: $targetPath" -ForegroundColor Yellow
                        }
                        
                        # Check if shortcut target matches keywords
                        if (Contains-Keyword $targetPath) {
                            $delete = $true
                            Write-Host "✓ Found keyword in shortcut target: $targetPath" -ForegroundColor Yellow
                        }
                    }
                } catch {
                    # Ignore shortcut read errors
                }
            }

            if ($delete) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed recent file: $($file.Name)" -ForegroundColor Green
                    $recentCount++
                } catch {
                    Write-Host "✗ Failed to remove recent file $($file.Name) : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

Write-Host "Enhanced Recent files cleanup completed. Files removed: $recentCount" -ForegroundColor Yellow

# PowerShell history cleanup
Write-Host "`nCleaning PowerShell history..." -ForegroundColor Cyan
$historyPaths = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\VisualStudioCode_host_history.txt",
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\Windows PowerShell_host_history.txt"
)

foreach ($historyPath in $historyPaths) {
    if (Test-Path $historyPath) {
        try {
            Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Removed PowerShell history: $historyPath" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed to remove PowerShell history $historyPath : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Event log clearing
Write-Host "`nClearing event logs..." -ForegroundColor Cyan
$eventLogs = @('Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'System', 'Application')

foreach ($log in $eventLogs) {
    try {
        wevtutil cl $log 2>&1 | Out-Null
        Write-Host "✓ Cleared event log: $log" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to clear event log $log : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Additional cleanup: Temp files (keyword targeted only)
Write-Host "`nCleaning temporary files..." -ForegroundColor Cyan
$tempPaths = @("$env:TEMP", "$env:SystemRoot\Temp")
foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath) {
        Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($keyword in $keywords) {
                if ($_.Name.ToLower() -match [regex]::Escape($keyword)) {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "✓ Removed temp file: $($_.Name)" -ForegroundColor Green
                        break
                    } catch {
                        # Ignore deletion errors for temp files
                    }
                }
            }
        }
    }
}

Write-Host "`n" + "="*50 -ForegroundColor Green
Write-Host "ENHANCED TARGETED CLEANUP COMPLETED!" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Green
Write-Host "Total registry items removed: $totalRemoved" -ForegroundColor Yellow
Write-Host "Total prefetch files removed: $prefetchCount" -ForegroundColor Yellow
Write-Host "Total recent files removed: $recentCount" -ForegroundColor Yellow
Write-Host "Detection capabilities:" -ForegroundColor Cyan
Write-Host "  • Keyword targeting (aimbot, usermode, MainRunner, etc.)" -ForegroundColor White
Write-Host "  • C++ files (.cpp)" -ForegroundColor White
Write-Host "  • AHK files and shortcuts" -ForegroundColor White
Write-Host "  • USB drive content (non-C: drives)" -ForegroundColor White
Write-Host "  • File content scanning in destination folders" -ForegroundColor White
Write-Host "Recommendation: Restart your computer to complete the cleanup process." -ForegroundColor Yellow
