#include "AutoStart/AutoStartScanner.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/RegKey.h"

#include <vector>

namespace GuardDog {
namespace Cleaners {

namespace {

constexpr wchar_t kAppInitKey[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
constexpr wchar_t kAppInitKeyWow64[] =
    L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
constexpr wchar_t kAppInitValue[] = L"AppInit_DLLs";
constexpr wchar_t kLoadAppInitValue[] = L"LoadAppInit_DLLs";

// AppInit_DLLs 是一个以空格或逗号分隔的 DLL 列表，要按项判断而不是整体判断——
// 否则一旦清空就要把用户的正常注入项一起丢掉。
std::vector<std::wstring> SplitDllList(const std::wstring& value) {
    std::vector<std::wstring> items;
    std::wstring current;

    for (const wchar_t ch : value) {
        if (ch == L' ' || ch == L',' || ch == L';' || ch == L'\t') {
            if (!current.empty()) {
                items.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        items.push_back(current);
    }

    return items;
}

std::wstring JoinDllList(const std::vector<std::wstring>& items) {
    std::wstring result;
    for (const std::wstring& item : items) {
        if (!result.empty()) {
            result += L' ';
        }
        result += item;
    }
    return result;
}

CleanResult CleanAppInitKey(HKEY root, const std::wstring& subKey, const Config& config, bool clean) {
    CleanResult result;

    RegKey key;
    if (!key.Open(root, subKey, KEY_READ | KEY_WRITE)) {
        return result;
    }

    std::wstring value;
    if (!ReadRegistryString(key.Get(), kAppInitValue, value) || value.empty()) {
        return result;  // 未配置注入项
    }

    ++result.scanned;

    const std::vector<std::wstring> items = SplitDllList(value);
    std::vector<std::wstring> survivors;
    std::vector<std::wstring> victims;

    for (const std::wstring& item : items) {
        if (IsTargetCommand(config, item)) {
            victims.push_back(item);
        } else {
            survivors.push_back(item);
        }
    }

    if (victims.empty()) {
        return result;
    }

    ++result.matched;
    for (const std::wstring& victim : victims) {
        ReportAutoStartHit(L"AppInit_DLLs", subKey + L"\\" + kAppInitValue, victim, clean);
    }

    if (!clean) {
        return result;
    }

    const std::wstring remaining = JoinDllList(survivors);
    if (!WriteRegistryString(key.Get(), kAppInitValue, remaining)) {
        ++result.failed;
        GD_LOG_ERROR(L"写回 AppInit_DLLs 失败：%s（错误 %lu）", subKey.c_str(), GetLastError());
        return result;
    }

    ++result.removed;
    GD_LOG_INFO(L"已从 AppInit_DLLs 移除 %llu 个注入项，剩余：%s",
                static_cast<unsigned long long>(victims.size()),
                remaining.empty() ? L"(空)" : remaining.c_str());

    // 列表清空后顺手关掉注入开关：留着 LoadAppInit_DLLs=1 而列表为空没有意义，
    // 反而方便下一个流氓软件直接往里塞 DLL 而不需要额外改开关。
    if (remaining.empty()) {
        DWORD enabled = 0;
        DWORD size = sizeof(enabled);
        DWORD type = 0;
        if (RegQueryValueExW(key.Get(), kLoadAppInitValue, nullptr, &type,
                             reinterpret_cast<LPBYTE>(&enabled), &size) == ERROR_SUCCESS &&
            type == REG_DWORD && enabled != 0) {
            const DWORD disabled = 0;
            if (RegSetValueExW(key.Get(), kLoadAppInitValue, 0, REG_DWORD,
                               reinterpret_cast<const BYTE*>(&disabled), sizeof(disabled)) ==
                ERROR_SUCCESS) {
                GD_LOG_INFO(L"已关闭 AppInit_DLLs 注入开关：%s", subKey.c_str());
            }
        }
    }

    return result;
}

} // namespace

CleanResult CleanAppInit(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    CleanResult result;
    result.Accumulate(CleanAppInitKey(HKEY_LOCAL_MACHINE, kAppInitKey, config, clean));
    result.Accumulate(CleanAppInitKey(HKEY_LOCAL_MACHINE, kAppInitKeyWow64, config, clean));
    return result;
}

} // namespace Cleaners
} // namespace GuardDog