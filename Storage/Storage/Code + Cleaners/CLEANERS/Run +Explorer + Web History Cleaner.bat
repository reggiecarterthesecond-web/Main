@echo off

:: — Clear Run box history
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f

:: — Clear File Explorer search history
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f

:: — Clear Explorer address‑bar history
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f

:: — Hide the Safely Remove Hardware (USB) icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\SysTray" /v Services /t REG_DWORD /d 29 /f

:: — Restart Explorer to apply history clearing
taskkill /f /im explorer.exe
start explorer.exe

:: — Refresh the tray icons to hide USB icon
start "" "%SystemRoot%\System32\systray.exe"

:: — Close all Notepad windows
taskkill /F /IM notepad.exe

echo.
echo Run & Explorer history cleared, USB icon hidden, and Notepad closed.
pause