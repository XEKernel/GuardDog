#include "AutoStart/AutoStartScanner.h"

#include "Core/ComPtr.h"
#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/RegKey.h"

#include <shlobj.h>
#include <shobjidl.h>

#include <vector>

namespace GuardDog {
namespace Cleaners {

namespace {

// 启动文件夹里的条目类型：快捷方式要解析出真实目标，其他按文件本身判定
constexpr const wchar_t* kStartupFilePatterns[] = {L"*.lnk", L"*.exe", L"*.bat", L"*.cmd",
                                                   L"*.url", L"*.vbs", L"*.js"};

constexpr wchar_t kStartupRelativePath[] =
    L"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";

std::wstring QueryKnownFolder(REFKNOWNFOLDERID folderId) {
    PWSTR rawPath = nullptr;
    std::wstring result;
    if (SUCCEEDED(SHGetKnownFolderPath(folderId, 0, nullptr, &rawPath)) && rawPath != nullptr) {
        result.assign(rawPath);
        CoTaskMemFree(rawPath);
    }
    return result;
}

// 解析 .lnk 的真实目标路径
std::wstring ResolveShortcutTarget(const std::wstring& shortcutPath) {
    ComPtr<IShellLinkW> link;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                reinterpret_cast<void**>(link.Put())))) {
        return std::wstring();
    }

    ComPtr<IPersistFile> persist;
    if (FAILED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(persist.Put())))) {
        return std::wstring();
    }

    if (FAILED(persist->Load(shortcutPath.c_str(), STGM_READ))) {
        return std::wstring();
    }

    wchar_t target[MAX_PATH * 2] = {};
    WIN32_FIND_DATAW findData{};
    if (FAILED(link->GetPath(target, _countof(target), &findData, SLGP_UNCPRIORITY))) {
        // 目标可能已被删除：此时 GetPath 返回空串但仍算解析"成功"
        return std::wstring();
    }
    return std::wstring(target);
}

// 收集所有需要检查的启动文件夹：
// 一是"所有用户"公共启动夹，二是每个用户配置目录下的启动夹。
// 服务跑在 LocalSystem 下，只查当前用户的启动夹会漏掉登录用户的项。
std::vector<std::wstring> CollectStartupFolders() {
    std::vector<std::wstring> folders;

    const std::wstring commonStartup = QueryKnownFolder(FOLDERID_CommonStartup);
    if (!commonStartup.empty()) {
        folders.push_back(commonStartup);
    }

    const std::wstring currentUserStartup = QueryKnownFolder(FOLDERID_Startup);
    if (!currentUserStartup.empty()) {
        folders.push_back(currentUserStartup);
    }

    // 从 ProfileList 枚举各用户的配置目录（比遍历 C:\Users 更准确，
    // 能拿到被重定向到其他盘的 profile 路径）
    RegKey profiles;
    if (profiles.Open(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS)) {
        DWORD index = 0;
        for (;;) {
            wchar_t sid[256] = {};
            DWORD sidLength = _countof(sid);
            if (RegEnumKeyExW(profiles.Get(), index, sid, &sidLength, nullptr, nullptr, nullptr,
                              nullptr) != ERROR_SUCCESS) {
                break;
            }
            ++index;

            RegKey profile;
            if (!profile.Open(profiles.Get(), sid, KEY_READ)) {
                continue;
            }

            std::wstring profilePath;
            if (!ReadRegistryString(profile.Get(), L"ProfileImagePath", profilePath) ||
                profilePath.empty()) {
                continue;
            }

            const std::wstring startup = profilePath + L"\\" + kStartupRelativePath;
            if (GetFileAttributesW(startup.c_str()) != INVALID_FILE_ATTRIBUTES) {
                folders.push_back(startup);
            }
        }
    }

    return folders;
}

CleanResult CleanOneFolder(const std::wstring& folder, const Config& config, bool clean) {
    CleanResult result;

    for (const wchar_t* pattern : kStartupFilePatterns) {
        const std::wstring searchPath = folder + L"\\" + pattern;

        WIN32_FIND_DATAW findData{};
        HANDLE find = FindFirstFileW(searchPath.c_str(), &findData);
        if (find == INVALID_HANDLE_VALUE) {
            continue;
        }

        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                continue;
            }

            ++result.scanned;
            const std::wstring entryPath = folder + L"\\" + findData.cFileName;
            const std::wstring fileName(findData.cFileName);

            // .lnk 要解析出真实目标再判断；其余文件本身就是可执行载体
            const bool isShortcut = fileName.size() > 4 &&
                                    _wcsicmp(fileName.c_str() + fileName.size() - 4, L".lnk") == 0;

            std::wstring candidate = entryPath;
            if (isShortcut) {
                const std::wstring target = ResolveShortcutTarget(entryPath);
                if (!target.empty()) {
                    candidate = target;
                }
            }

            if (!IsTargetCommand(config, candidate)) {
                continue;
            }

            ++result.matched;
            ReportAutoStartHit(L"启动文件夹", entryPath, candidate, clean);

            if (!clean) {
                continue;
            }

            // 只删除启动项本身（快捷方式/文件），源程序的删除由文件处置模块负责，
            // 这样职责边界清晰，也不会在这里误删用户目录里的正常文件。
            if (DeleteFileForce(entryPath)) {
                ++result.removed;
                GD_LOG_INFO(L"已删除启动项：%s", entryPath.c_str());
            } else {
                ++result.failed;
                GD_LOG_ERROR(L"删除启动项失败：%s", entryPath.c_str());
            }
        } while (FindNextFileW(find, &findData));

        FindClose(find);
    }

    return result;
}

} // namespace

CleanResult CleanStartupFolder(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    ScopedCom com;
    if (!com.IsUsable()) {
        GD_LOG_WARN(L"COM 不可用，跳过启动文件夹检查");
        return CleanResult{};
    }

    CleanResult result;
    for (const std::wstring& folder : CollectStartupFolders()) {
        result.Accumulate(CleanOneFolder(folder, config, clean));
    }
    return result;
}

} // namespace Cleaners
} // namespace GuardDog