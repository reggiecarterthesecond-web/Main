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
#include <conio.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")

#define WIN32_LEAN_AND_MEAN

std::atomic<bool> usbPluggedIn(false);
std::atomic<bool> exclusionActive(false);
std::atomic<bool> shouldExit(false);
std::atomic<bool> useDeepCleaner(false);
std::atomic<bool> showMonitor(false);

PROCESS_INFORMATION pi = {0};
std::vector<PROCESS_INFORMATION> aimbotProcesses;

struct Settings {
    bool enableCursorChanger = true;
    bool enableAVBypass = true;
    bool closeAppOnUSBUnplug = false;
    bool autoRunCleanerOnUSB = true;
    bool runAimbotUnlocker = true;
    
    std::vector<std::wstring> aimbotUnlockerPaths = {L"J:\\Storage\\AimbotUnlocker.exe"};
    
    std::vector<std::wstring> exePaths = {L"J:\\Matcha\\usermode\\app.exe"};
    
    std::vector<std::wstring> storageFolders = {L"J:\\Storage\\matcha"};
    std::vector<std::wstring> tempFolders = {L"C:\\matcha"};
    std::vector<std::wstring> exclusionPaths = {L"J:"};
    
    std::vector<std::wstring> startAppKeys = {L"VK_PRIOR"};
    std::vector<std::wstring> stopAppKeys = {L"VK_END"};
    std::vector<std::wstring> runCleanerKeys = {L"VK_HOME"};
    
    std::wstring CleanerLink = L"https://raw.githubusercontent.com/TheMasterHacker2244/newui/refs/heads/main/Cleaner.ps1";
    std::wstring DeepCleanerLink = L"https://raw.githubusercontent.com/TheMasterHacker2244/newui/refs/heads/main/DeepCleaner.ps1";
    std::wstring PowerShellPlugin = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/PluginPowerShell.ps1";
    std::wstring PowerShellEject = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/EjectPowerShell.ps1";
    std::wstring CursorsToArrowLink = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/CursorsToArrow.ps1";
    std::wstring DefaultCursorsLink = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/DefaultCursors.ps1";
    
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

// Forward declarations
void RunPowerShellScriptHidden(const std::wstring& url);
void ExecutePowerShellFromURL(const std::wstring& url);
void ExecuteHiddenPowerShell(const std::wstring& command);
void ExecutePowerShellAsAdmin(const std::wstring& command);
bool IsRunningAsAdmin();
void HideConsole();
void ShowConsole();

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
    settings.runAimbotUnlocker = ExtractJsonBool(cleanJson, L"runAimbotUnlocker");
    
    settings.aimbotUnlockerPaths = ExtractJsonStringArray(cleanJson, L"aimbotUnlockerPaths");
    if (settings.aimbotUnlockerPaths.empty()) {
        std::wstring singlePath = ExtractJsonString(cleanJson, L"aimbotUnlockerPath");
        if (!singlePath.empty()) {
            settings.aimbotUnlockerPaths.push_back(singlePath);
        } else {
            settings.aimbotUnlockerPaths = {L"J:\\Storage\\AimbotUnlocker.exe"};
        }
    }
    
    settings.exePaths = ExtractJsonStringArray(cleanJson, L"exePaths");
    
    settings.storageFolders = ExtractJsonStringArray(cleanJson, L"storageFolders");
    settings.tempFolders = ExtractJsonStringArray(cleanJson, L"tempFolders");
    settings.exclusionPaths = ExtractJsonStringArray(cleanJson, L"exclusionPaths");
    
    settings.startAppKeys = ExtractJsonStringArray(cleanJson, L"startAppKeys");
    settings.stopAppKeys = ExtractJsonStringArray(cleanJson, L"stopAppKeys");
    settings.runCleanerKeys = ExtractJsonStringArray(cleanJson, L"runCleanerKeys");
    
    settings.CleanerLink = ExtractJsonString(cleanJson, L"CleanerLink");
    settings.DeepCleanerLink = ExtractJsonString(cleanJson, L"DeepCleanerLink");
    settings.PowerShellPlugin = ExtractJsonString(cleanJson, L"PowerShellPlugin");
    settings.PowerShellEject = ExtractJsonString(cleanJson, L"PowerShellEject");
    settings.CursorsToArrowLink = ExtractJsonString(cleanJson, L"CursorsToArrowLink");
    settings.DefaultCursorsLink = ExtractJsonString(cleanJson, L"DefaultCursorsLink");
    
    settings.runPluginPowershell = ExtractJsonBool(cleanJson, L"runPluginPowershell");
    settings.runEjectPowershell = ExtractJsonBool(cleanJson, L"runEjectPowershell");
    
    settings.MapperDeletion = ExtractJsonBool(cleanJson, L"MapperDeletion");
    
    settings.usbCheckInterval = ExtractJsonInt(cleanJson, L"usbCheckInterval");
    settings.settingsCheckInterval = ExtractJsonInt(cleanJson, L"settingsCheckInterval");
    
    if (settings.CleanerLink.empty()) {
        settings.CleanerLink = L"https://raw.githubusercontent.com/TheMasterHacker2244/newui/refs/heads/main/Cleaner.ps1";
    }
    
    if (settings.DeepCleanerLink.empty()) {
        settings.DeepCleanerLink = L"https://raw.githubusercontent.com/TheMasterHacker2244/newui/refs/heads/main/DeepCleaner.ps1";
    }
    
    if (settings.PowerShellPlugin.empty()) {
        settings.PowerShellPlugin = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/PluginPowerShell.ps1";
    }
    
    if (settings.PowerShellEject.empty()) {
        settings.PowerShellEject = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/EjectPowerShell.ps1";
    }
    
    if (settings.CursorsToArrowLink.empty()) {
        settings.CursorsToArrowLink = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/CursorsToArrow.ps1";
    }
    
    if (settings.DefaultCursorsLink.empty()) {
        settings.DefaultCursorsLink = L"https://github.com/TheMasterHacker2244/newui/raw/refs/heads/main/DefaultCursors.ps1";
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
    
    if (showMonitor) {
        std::wcout << L"Running plugin script: " << currentSettings.PowerShellPlugin << std::endl;
    }
    ExecutePowerShellFromURL(currentSettings.PowerShellPlugin);
}

void RunEjectScript() {
    if (!currentSettings.runEjectPowershell || currentSettings.PowerShellEject.empty()) return;
    
    if (showMonitor) {
        std::wcout << L"Running eject script: " << currentSettings.PowerShellEject << std::endl;
    }
    ExecutePowerShellFromURL(currentSettings.PowerShellEject);
}

void RunSystemTrayScript() {
    std::wstring command = L"reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray\" /v \"Services\" /t reg_dword /d 29 /f; systray";
    ExecuteHiddenCommand(command);
}

void SetCursorsToArrow() {
    if (!currentSettings.enableCursorChanger) return;
    
    if (showMonitor) {
        std::wcout << L"Setting cursors to arrow..." << std::endl;
    }
    
    // Run the cursor script in a separate PowerShell process
    ExecutePowerShellFromURL(currentSettings.CursorsToArrowLink);
}

void RestoreDefaultCursors() {
    if (!currentSettings.enableCursorChanger) return;
    
    if (showMonitor) {
        std::wcout << L"Restoring default cursors..." << std::endl;
    }
    
    // Run the default cursor script in a separate PowerShell process
    ExecutePowerShellFromURL(currentSettings.DefaultCursorsLink);
}

void UpdateSettings() {
    static Settings lastSettings;
    Settings settings = LoadSettings();
    
    if (settings.enableCursorChanger != lastSettings.enableCursorChanger) {
        if (settings.enableCursorChanger && usbPluggedIn) {
            ExecutePowerShellFromURL(settings.CursorsToArrowLink);
        } else if (!settings.enableCursorChanger) {
            ExecutePowerShellFromURL(settings.DefaultCursorsLink);
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

void CloseProcessesInTempFolder(const std::wstring& folderPath) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(hSnap, &pe)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProcess) {
                wchar_t processPath[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
                    std::wstring fullPath(processPath);
                    // Check if the process path starts with the temp folder path
                    if (fullPath.find(folderPath) == 0) {
                        if (showMonitor) {
                            std::wcout << L"Closing process in temp folder: " << pe.szExeFile << std::endl;
                        }
                        TerminateProcess(hProcess, 0);
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
}

bool ForceDeleteFolder(const std::wstring& folderPath) {
    if (!currentSettings.MapperDeletion) {
        if (showMonitor) {
            std::wcout << L"MapperDeletion is disabled - skipping deletion of: " << folderPath << std::endl;
        }
        return false;
    }
    
    // Close all processes running from this folder first
    CloseProcessesInTempFolder(folderPath);
    
    // Wait a bit for processes to close
    Sleep(1000);
    
    std::wstring command = L"rd /s /q \"" + folderPath + L"\" 2>nul";
    ExecuteHiddenCommand(command);
    
    bool deleted = (GetFileAttributesW(folderPath.c_str()) == INVALID_FILE_ATTRIBUTES);
    if (showMonitor) {
        if (deleted) {
            std::wcout << L"Successfully deleted folder: " << folderPath << std::endl;
        } else {
            std::wcout << L"Failed to delete folder: " << folderPath << std::endl;
        }
    }
    
    return deleted;
}

bool CopyStorageFolder() {
    if (!currentSettings.MapperDeletion) {
        if (showMonitor) {
            std::wcout << L"MapperDeletion disabled - skipping folder copy" << std::endl;
        }
        return true; // Return true since we don't need to copy when MapperDeletion is disabled
    }
    
    std::wstring sourceFolder;
    for (const auto& folder : currentSettings.storageFolders) {
        if (GetFileAttributesW(folder.c_str()) != INVALID_FILE_ATTRIBUTES) {
            sourceFolder = folder;
            break;
        }
    }
    
    if (sourceFolder.empty()) {
        if (showMonitor) {
            std::wcout << L"No source storage folder found!" << std::endl;
        }
        return false;
    }
    
    std::wstring destFolder = currentSettings.tempFolders.empty() ? L"C:\\matcha" : currentSettings.tempFolders[0];
    
    // Close processes and delete existing folder
    ForceDeleteFolder(destFolder);
    
    std::wstring command = L"xcopy \"" + sourceFolder + L"\" \"" + destFolder + L"\" /E /I /H /Y >nul 2>&1";
    ExecuteHiddenCommand(command);
    
    DWORD newAttr = GetFileAttributesW(destFolder.c_str());
    bool success = (newAttr != INVALID_FILE_ATTRIBUTES && (newAttr & FILE_ATTRIBUTE_DIRECTORY));
    
    if (showMonitor) {
        if (success) {
            std::wcout << L"Successfully copied storage folder to: " << destFolder << std::endl;
        } else {
            std::wcout << L"Failed to copy storage folder to: " << destFolder << std::endl;
        }
    }
    
    return success;
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
    if (!currentSettings.runAimbotUnlocker || currentSettings.aimbotUnlockerPaths.empty()) return;
    
    bool started = false;
    
    for (const auto& path : currentSettings.aimbotUnlockerPaths) {
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            if (showMonitor) {
                std::wcout << L"AimbotUnlocker not found: " << path << std::endl;
            }
            continue;
        }
        
        size_t lastSlash = path.find_last_of(L"\\");
        std::wstring processName = (lastSlash != std::wstring::npos) ? 
            path.substr(lastSlash + 1) : path;
        
        if (IsProcessRunning(processName)) {
            if (showMonitor) {
                std::wcout << L"AimbotUnlocker is already running: " << processName << std::endl;
            }
            started = true;
            break;
        }

        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION localPi = {0};
        wchar_t* cmd = _wcsdup(path.c_str());

        if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &localPi)) {
            aimbotProcesses.push_back(localPi);
            if (showMonitor) {
                std::wcout << L"Started AimbotUnlocker: " << path << std::endl;
            }
            started = true;
            free(cmd);
            break;
        } else {
            if (showMonitor) {
                std::wcout << L"Failed to start AimbotUnlocker: " << path << " - Error: " << GetLastError() << std::endl;
            }
        }
        
        free(cmd);
    }
    
    if (!started && showMonitor) {
        std::wcout << L"Could not start any AimbotUnlocker from the provided paths." << std::endl;
    }
}

void StopAimbotUnlocker() {
    if (!currentSettings.runAimbotUnlocker || currentSettings.aimbotUnlockerPaths.empty()) return;
    
    for (auto& pi : aimbotProcesses) {
        if (pi.hProcess != NULL) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    aimbotProcesses.clear();
    
    for (const auto& path : currentSettings.aimbotUnlockerPaths) {
        size_t lastSlash = path.find_last_of(L"\\");
        std::wstring processName = (lastSlash != std::wstring::npos) ? 
            path.substr(lastSlash + 1) : path;
        
        StopProcessByName(processName);
    }
    
    if (showMonitor) {
        std::wcout << L"Stopped all AimbotUnlocker instances" << std::endl;
    }
}

void StartApp() {
    if (!IsUSBAvailable()) {
        if (showMonitor) {
            std::wcout << L"Cannot start app - USB not available" << std::endl;
        }
        return;
    }
    
    if (IsProcessRunning(L"app.exe")) {
        if (showMonitor) {
            std::wcout << L"App is already running" << std::endl;
        }
        return;
    }
    
    // Only copy storage folder if MapperDeletion is enabled
    if (currentSettings.MapperDeletion) {
        if (!CopyStorageFolder()) {
            if (showMonitor) {
                std::wcout << L"Failed to copy storage folder - cannot start app" << std::endl;
            }
            return;
        }
    }

    std::wstring exePath;
    for (const auto& path : currentSettings.exePaths) {
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            exePath = path;
            break;
        }
    }
    
    if (exePath.empty()) {
        if (showMonitor) {
            std::wcout << L"No valid executable path found!" << std::endl;
        }
        return;
    }

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION localPi = {0};
    wchar_t* cmd = _wcsdup(exePath.c_str());

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &localPi)) {
        pi = localPi;
        if (showMonitor) {
            std::wcout << L"Started app: " << exePath << std::endl;
        }
    } else {
        if (showMonitor) {
            std::wcout << L"Failed to start app: " << GetLastError() << std::endl;
        }
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

void RunCleaner() {
    if (useDeepCleaner) {
        if (showMonitor) {
            std::wcout << L"Running Deep Cleaner as admin: " << currentSettings.DeepCleanerLink << std::endl;
        }
        ExecutePowerShellAsAdmin(L"Invoke-Expression (Invoke-WebRequest '" + currentSettings.DeepCleanerLink + L"' -UseBasicParsing).Content");
    } else {
        RunPowerShellScriptHidden(currentSettings.CleanerLink);
    }
}

void HideConsole() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
}

void ShowConsole() {
    ShowWindow(GetConsoleWindow(), SW_SHOW);
}

void ShowStartupMenu() {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONIN$", "r", stdin);
    
    std::cout << "==============================================" << std::endl;
    std::cout << "           T1/T2 Larp Bypass" << std::endl;
    std::cout << "==============================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Select an option:" << std::endl;
    std::cout << "1. Default Mode (Regular Cleaner, No Monitor)" << std::endl;
    std::cout << "2. Deep Clean Mode (Admin Deep Cleaner, No Monitor)" << std::endl;
    std::cout << "3. Debug Mode (Regular Cleaner, With Monitor)" << std::endl;
    std::cout << "4. Debug Deep Clean Mode (Admin Deep Cleaner, With Monitor)" << std::endl;
    std::cout << std::endl;
    std::cout << "Enter your choice (1-4): ";
    
    int choice = 0;
    std::cin >> choice;
    
    switch (choice) {
        case 1:
            useDeepCleaner = false;
            showMonitor = false;
            std::cout << "Default Mode selected! (No Monitor)" << std::endl;
            break;
        case 2:
            useDeepCleaner = true;
            showMonitor = false;
            std::cout << "Deep Clean Mode selected! (No Monitor)" << std::endl;
            break;
        case 3:
            useDeepCleaner = false;
            showMonitor = true;
            std::cout << "Debug Mode selected! (With Monitor)" << std::endl;
            break;
        case 4:
            useDeepCleaner = true;
            showMonitor = true;
            std::cout << "Debug Deep Clean Mode selected! (With Monitor)" << std::endl;
            break;
        default:
            useDeepCleaner = false;
            showMonitor = false;
            std::cout << "Invalid choice, Default Mode selected! (No Monitor)" << std::endl;
            break;
    }
    
    std::cout << "Starting monitor..." << std::endl;
    std::cout << "Application will continue running in background." << std::endl;
    std::cout << "You can close this window - the monitor will keep running." << std::endl;
    std::cout << "==============================================" << std::endl;
    
    // Hide console for non-monitor modes
    if (!showMonitor) {
        HideConsole();
    }
}

void HandleUSBStateChange(bool usbNowAvailable) {
    if (usbNowAvailable) {
        if (showMonitor) {
            std::wcout << L"=== USB PLUGGED IN - STARTING SETUP ===" << std::endl;
        }
        
        UpdateSettings();
        
        if (showMonitor) {
            std::wcout << L"1. Setting Defender exclusions..." << std::endl;
        }
        ToggleDefenderExclusion(true);
        
        if (showMonitor) {
            std::wcout << L"2. Running plugin script..." << std::endl;
        }
        RunPluginScript();
        
        if (showMonitor) {
            std::wcout << L"3. Running system tray script..." << std::endl;
        }
        RunSystemTrayScript();
        
        if (currentSettings.enableCursorChanger) {
            if (showMonitor) {
                std::wcout << L"4. Setting cursors to arrow..." << std::endl;
            }
            SetCursorsToArrow();
        }
        
        if (currentSettings.autoRunCleanerOnUSB) {
            if (showMonitor) {
                std::wcout << L"5. Running cleaner..." << std::endl;
            }
            RunCleaner();
        }
        
        // Only copy storage folder if MapperDeletion is enabled
        if (currentSettings.MapperDeletion) {
            if (showMonitor) {
                std::wcout << L"6. Copying storage folder..." << std::endl;
            }
            CopyStorageFolder();
        }
        
        if (currentSettings.runAimbotUnlocker) {
            if (showMonitor) {
                std::wcout << L"7. Starting AimbotUnlocker (LAST STEP)..." << std::endl;
            }
            StartAimbotUnlocker();
        }
        
        if (showMonitor) {
            std::wcout << L"=== USB SETUP COMPLETE! ===" << std::endl;
        }
    } else {
        if (showMonitor) {
            std::wcout << L"=== USB UNPLUGGED - CLEANING UP ===" << std::endl;
        }
        
        if (currentSettings.runAimbotUnlocker) {
            if (showMonitor) {
                std::wcout << L"1. Stopping AimbotUnlocker (FIRST STEP)..." << std::endl;
            }
            StopAimbotUnlocker();
        }
        
        if (showMonitor) {
            std::wcout << L"2. Removing Defender exclusions..." << std::endl;
        }
        ToggleDefenderExclusion(false);
        
        if (showMonitor) {
            std::wcout << L"3. Running eject script..." << std::endl;
        }
        RunEjectScript();
        
        if (currentSettings.enableCursorChanger) {
            if (showMonitor) {
                std::wcout << L"4. Restoring default cursors..." << std::endl;
            }
            RestoreDefaultCursors();
        }
        
        if (currentSettings.autoRunCleanerOnUSB) {
            if (showMonitor) {
                std::wcout << L"5. Running cleaner..." << std::endl;
            }
            RunCleaner();
        }
        
        if (currentSettings.closeAppOnUSBUnplug) {
            if (showMonitor) {
                std::wcout << L"6. Stopping app..." << std::endl;
            }
            StopApp();
        }
        
        Sleep(1000);
        
        if (currentSettings.MapperDeletion) {
            for (const auto& tempFolder : currentSettings.tempFolders) {
                if (showMonitor) {
                    std::wcout << L"7. Deleting temp folder: " << tempFolder << std::endl;
                }
                ForceDeleteFolder(tempFolder);
            }
        } else {
            if (showMonitor) {
                std::wcout << L"7. MapperDeletion disabled - keeping temp folders" << std::endl;
            }
        }
        
        if (showMonitor) {
            std::wcout << L"=== USB CLEANUP COMPLETE! ===" << std::endl;
        }
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
    // Show startup menu first
    ShowStartupMenu();
    
    if (!IsRunningAsAdmin()) {
        RunAsAdmin();
    }
    
    currentSettings = LoadSettings();
    UpdateSettings();
    
    if (showMonitor) {
        // Only allocate new console if the startup menu console was closed
        if (GetConsoleWindow() == NULL) {
            AllocConsole();
            FILE* f;
            freopen_s(&f, "CONOUT$", "w", stdout);
            freopen_s(&f, "CONOUT$", "w", stderr);
        } else {
            ShowConsole();
        }
        std::wcout << L"=== T1/T2 LARP BYPASS STARTED ===" << std::endl;
    } else {
        // Ensure console is hidden for non-monitor modes
        HideConsole();
    }
    
    usbPluggedIn = IsUSBAvailable();
    if (showMonitor) {
        std::wcout << L"Initial USB state: " << (usbPluggedIn ? L"PLUGGED IN" : L"NOT PLUGGED IN") << std::endl;
        std::wcout << L"Run plugin powershell: " << (currentSettings.runPluginPowershell ? L"ENABLED" : L"DISABLED") << std::endl;
        std::wcout << L"Run eject powershell: " << (currentSettings.runEjectPowershell ? L"ENABLED" : L"DISABLED") << std::endl;
        std::wcout << L"Mapper deletion: " << (currentSettings.MapperDeletion ? L"ENABLED" : L"DISABLED") << std::endl;
        std::wcout << L"Close app on USB unplug: " << (currentSettings.closeAppOnUSBUnplug ? L"ENABLED" : L"DISABLED") << std::endl;
        std::wcout << L"Run AimbotUnlocker: " << (currentSettings.runAimbotUnlocker ? L"ENABLED" : L"DISABLED") << std::endl;
        std::wcout << L"Cleaner mode: " << (useDeepCleaner ? L"DEEP CLEAN" : L"REGULAR") << std::endl;
        std::wcout << L"Monitor: " << (showMonitor ? L"ENABLED" : L"DISABLED") << std::endl;
        std::wcout << L"AimbotUnlocker paths:" << std::endl;
        for (const auto& path : currentSettings.aimbotUnlockerPaths) {
            std::wcout << L"  - " << path << std::endl;
        }
    }
    
    HandleUSBStateChange(usbPluggedIn);
    
    std::thread usbThread(USBMONITOR);
    std::thread settingsThread(SettingsMonitor);
    
    RegisterHotKeys();

    if (showMonitor) {
        std::wcout << L"Monitoring started. Press hotkeys to control app." << std::endl;
        std::wcout << L"You can close this window - the monitor will keep running." << std::endl;
    }
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) && !shouldExit) {
        if (msg.message == WM_HOTKEY) {
            if (showMonitor) {
                // Reopen console if it was closed
                if (GetConsoleWindow() == NULL) {
                    AllocConsole();
                    FILE* f;
                    freopen_s(&f, "CONOUT$", "w", stdout);
                    freopen_s(&f, "CONOUT$", "w", stderr);
                    ShowConsole();
                }
                
                switch (msg.wParam) {
                    case 1:
                        if (usbPluggedIn) {
                            std::wcout << L"HOTKEY: Starting app..." << std::endl;
                            StartApp();
                        } else {
                            std::wcout << L"HOTKEY: Cannot start app - USB not available" << std::endl;
                        }
                        break;
                    case 2:
                        std::wcout << L"HOTKEY: Stopping app..." << std::endl;
                        StopApp();
                        break;
                    case 3:
                        std::wcout << L"HOTKEY: Running cleaner..." << std::endl;
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
    
    if (showMonitor && GetConsoleWindow() != NULL) {
        std::wcout << L"=== SHUTTING DOWN ===" << std::endl;
    }
    
    shouldExit = true;
    StopApp();
    StopAimbotUnlocker();
    
    if (exclusionActive) {
        if (showMonitor && GetConsoleWindow() != NULL) {
            std::wcout << L"Cleaning up Defender exclusions..." << std::endl;
        }
        ToggleDefenderExclusion(false);
    }
    
    UnregisterHotKey(NULL, 1);
    UnregisterHotKey(NULL, 2);
    UnregisterHotKey(NULL, 3);
    
    if (usbThread.joinable()) usbThread.join();
    if (settingsThread.joinable()) settingsThread.join();
    
    if (showMonitor && GetConsoleWindow() != NULL) {
        std::wcout << L"=== SHUTDOWN COMPLETE ===" << std::endl;
    }
    
    return 0;
}