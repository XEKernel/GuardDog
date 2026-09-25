#include "Cleaner/LegacyScanner.h"

#include "AutoStart/AutoStartTypes.h"
#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"
#include "Core/RegKey.h"
#include "Monitor/ProcessPoller.h"

#include <shlobj.h>

#include <algorithm>
#include <vector>

#pragma comment(lib, "shell32.lib")

namespace GuardDog {

namespace {

// 只对可执行载体做判定：对 dll/sys 之外的资源文件做匹配没有意义
bool IsExecutableCarrier(const std::wstring& fileName) {
    const size_t dot = fileName.find_last_of(L'.');
    if (dot == std::wstring::npos) {
        return false;
    }
    const std::wstring extension = fileName.substr(dot);
    return _wcsicmp(extension.c_str(), L".exe") == 0 ||
           _wcsicmp(extension.c_str(), L".dll") == 0 ||
           _wcsicmp(extension.c_str(), L".sys") == 0 ||
           _wcsicmp(extension.c_str(), L".com") == 0;
}

std::wstring QueryKnownFolder(REFKNOWNFOLDERID folderId) {
    PWSTR rawPath = nullptr;
    std::wstring result;
    if (SUCCEEDED(SHGetKnownFolderPath(folderId, 0, nullptr, &rawPath)) && rawPath != nullptr) {
        result.assign(rawPath);
        CoTaskMemFree(rawPath);
    }
    return result;
}

// 扫描一个目录的"第一层"文件。
// 刻意不递归：流氓软件的安装目录通常很浅，而全盘/深层递归既慢又容易误伤
// （例如某个软件目录下嵌套着用户自己编译的测试程序）。
void ScanFlatDirectory(const std::wstring& directory, const Config& config,
                       const std::wstring& source, LegacyScanResult& result) {
    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            continue;
        }

        const std::wstring fileName(findData.cFileName);
        if (!IsExecutableCarrier(fileName)) {
            continue;
        }

        ++result.filesChecked;
        const std::wstring filePath = directory + L"\\" + fileName;

        if (!Matcher::IsInBlacklist(config, filePath)) {
            continue;
        }

        result.hits.push_back(
            LegacyScanResult::Hit{filePath, 0, source, L"目录内可执行文件命中"});
    } while (FindNextFileW(find, &findData));

    FindClose(find);
}

// E1：遍历 Uninstall 注册表键
void ScanUninstallKey(HKEY root, const std::wstring& keyPath, const wchar_t* rootName,
                      const Config& config, LegacyScanResult& result) {
    RegKey uninstall;
    if (!uninstall.Open(root, keyPath, KEY_READ | KEY_ENUMERATE_SUB_KEYS)) {
        return;
    }

    DWORD index = 0;
    for (;;) {
        wchar_t subKeyName[512] = {};
        DWORD nameLength = _countof(subKeyName);
        if (RegEnumKeyExW(uninstall.Get(), index, subKeyName, &nameLength, nullptr, nullptr, nullptr,
                          nullptr) != ERROR_SUCCESS) {
            break;
        }
        ++index;

        RegKey entry;
        if (!entry.Open(uninstall.Get(), subKeyName, KEY_READ)) {
            continue;
        }

        std::wstring displayName;
        std::wstring installLocation;
        std::wstring uninstallString;
        std::wstring publisher;
        ReadRegistryString(entry.Get(), L"DisplayName", displayName);
        ReadRegistryString(entry.Get(), L"InstallLocation", installLocation);
        ReadRegistryString(entry.Get(), L"UninstallString", uninstallString);
        ReadRegistryString(entry.Get(), L"Publisher", publisher);

        // 既没有名字也没有安装目录的条目（系统补丁、更新缓存）跳过
        if (displayName.empty() && installLocation.empty()) {
            continue;
        }

        ++result.installedChecked;

        std::wstring detail;
        bool matched = false;

        // 判据一：卸载程序本身是不是黑名单目标。
        // 命中它意味着"这个软件就是我们要找的"，同时防止用户误点卸载反而触发流氓行为。
        if (!uninstallString.empty()) {
            const std::wstring uninstallExe = ExtractExecutablePath(uninstallString);
            if (!uninstallExe.empty() && Matcher::IsInBlacklist(config, uninstallExe)) {
                matched = true;
                detail = L"卸载程序命中：" + uninstallString;
            }
        }

        // 判据二：安装目录里是否存在黑名单文件
        if (!installLocation.empty()) {
            const size_t hitsBefore = result.hits.size();
            ScanFlatDirectory(installLocation, config, L"已安装程序", result);
            if (result.hits.size() > hitsBefore) {
                matched = true;
                if (!detail.empty()) {
                    detail += L"；";
                }
                detail += L"安装目录命中：" + installLocation;
            }
        }

        if (!matched) {
            continue;
        }

        ++result.installedMatched;
        GD_LOG_WARN(L"存量扫描：已安装程序命中 → %s（%s）", displayName.c_str(), detail.c_str());

        // 把完整信息写入日志：用户需要这些字段来判断是否误报，以及手工恢复
        Logger::Instance().LogBackup(
            L"已安装程序",
            (std::wstring(rootName) + L"\\" + keyPath + L"\\" + subKeyName).c_str(),
            L"显示名=[" + displayName + L"] 发布者=[" + publisher + L"] 安装目录=[" + installLocation +
                L"] 卸载命令=[" + uninstallString + L"]");
    }
}

// E3：常见安装目录
void ScanCommonInstallRoots(const Config& config, LegacyScanResult& result) {
    std::vector<std::wstring> roots;
    const std::wstring localAppData = QueryKnownFolder(FOLDERID_LocalAppData);
    const std::wstring appData = QueryKnownFolder(FOLDERID_RoamingAppData);
    const std::wstring programData = QueryKnownFolder(FOLDERID_ProgramData);

    std::vector<std::wstring> candidates;
    candidates.push_back(QueryKnownFolder(FOLDERID_ProgramFilesX64));
    candidates.push_back(QueryKnownFolder(FOLDERID_ProgramFilesX86));
    candidates.push_back(QueryKnownFolder(FOLDERID_ProgramFiles));
    candidates.push_back(localAppData);
    candidates.push_back(appData);
    candidates.push_back(programData);

    for (const std::wstring& candidate : candidates) {
        if (candidate.empty()) {
            continue;
        }
        const DWORD attributes = GetFileAttributesW(candidate.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            roots.push_back(candidate);
        }
    }

    for (const std::wstring& root : roots) {
        WIN32_FIND_DATAW findData{};
        HANDLE find = FindFirstFileW((root + L"\\*").c_str(), &findData);
        if (find == INVALID_HANDLE_VALUE) {
            continue;
        }

        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                continue;
            }
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
                continue;
            }

            ++result.directoriesChecked;
            ScanFlatDirectory(root + L"\\" + findData.cFileName, config, L"安装目录", result);
        } while (FindNextFileW(find, &findData));

        FindClose(find);
    }
}

} // namespace

std::wstring LegacyScanResult::Describe() const {
    wchar_t buffer[320] = {};
    swprintf_s(buffer,
               L"已安装程序 %d/%d 命中，运行进程 %d 个（命中 %llu 个），"
               L"安装目录 %d 个、文件 %d 个（命中 %llu 个）",
               installedMatched, installedChecked, processesChecked,
               static_cast<unsigned long long>(
                   std::count_if(hits.begin(), hits.end(), [](const Hit& hit) {
                       return hit.processId != 0;
                   })),
               directoriesChecked, filesChecked,
               static_cast<unsigned long long>(hits.size()));
    return std::wstring(buffer);
}

LegacyScanResult LegacyScanner::Scan(const Config& config) {
    LegacyScanResult result;

    GD_LOG_INFO(L"===== 开始存量扫描（已安装程序 / 运行进程 / 常见安装目录）=====");

    // ---- E1 已安装程序 ----
    ScanUninstallKey(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", L"HKLM",
                     config, result);
    ScanUninstallKey(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                     L"HKLM\\WOW6432Node", config, result);
    ScanUninstallKey(HKEY_CURRENT_USER,
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", L"HKCU",
                     config, result);

    // ---- E2 运行进程（复用轮询扫描器，保持判定逻辑一致）----
    {
        ProcessPoller poller;
        poller.ScanNow(config, [&result](DWORD processId, const std::wstring& imagePath) {
            result.hits.push_back(
                LegacyScanResult::Hit{imagePath, processId, L"运行进程", L"存量进程命中"});
        });
    }

    // ---- E3 常见安装目录 ----
    ScanCommonInstallRoots(config, result);

    GD_LOG_INFO(L"存量扫描完成：%s", result.Describe().c_str());
    for (const LegacyScanResult::Hit& hit : result.hits) {
        GD_LOG_WARN(L"存量扫描命中项：来源=%s 类型=%s 路径=%s", hit.source.c_str(),
                    hit.processId != 0 ? L"运行中进程" : L"静态文件", hit.path.c_str());
    }

    return result;
}

} // namespace GuardDog