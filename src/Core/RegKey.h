#pragma once

#include <windows.h>

#include <string>

namespace GuardDog {

// 注册表键的 RAII 封装。
// RegCloseKey 与 CloseHandle 语义不同，所以不能复用 ScopeHandle；
// 而清理模块会遍历大量注册表分支，任何早期 return 都会漏关句柄。
class RegKey {
public:
    RegKey() noexcept = default;
    ~RegKey() { Close(); }

    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;

    RegKey(RegKey&& other) noexcept : m_key(other.m_key) { other.m_key = nullptr; }

    RegKey& operator=(RegKey&& other) noexcept {
        if (this != &other) {
            Close();
            m_key = other.m_key;
            other.m_key = nullptr;
        }
        return *this;
    }

    // 打开已存在的子键；不存在则返回 false（不会创建）
    bool Open(HKEY root, const std::wstring& subKey, REGSAM access = KEY_READ) noexcept {
        Close();
        return RegOpenKeyExW(root, subKey.c_str(), 0, access, &m_key) == ERROR_SUCCESS;
    }

    // 创建或打开子键（用于需要写入的场景）
    bool Create(HKEY root, const std::wstring& subKey,
                REGSAM access = KEY_READ | KEY_WRITE) noexcept {
        Close();
        DWORD disposition = 0;
        return RegCreateKeyExW(root, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, access,
                               nullptr, &m_key, &disposition) == ERROR_SUCCESS;
    }

    HKEY Get() const noexcept { return m_key; }
    bool IsValid() const noexcept { return m_key != nullptr; }

    // 接收出参用（先关闭旧句柄，避免覆盖泄漏）
    HKEY* Put() noexcept {
        Close();
        return &m_key;
    }

    void Close() noexcept {
        if (m_key != nullptr) {
            RegCloseKey(m_key);
            m_key = nullptr;
        }
    }

private:
    HKEY m_key = nullptr;
};

// 读取字符串值（REG_SZ / REG_EXPAND_SZ，后者自动展开环境变量）。
// 之所以要展开：服务里读到的 ImagePath 常写成 "%ProgramFiles%\X\a.exe"，
// 不展开就没法与黑名单里的绝对路径比较。
inline bool ReadRegistryString(HKEY key, const wchar_t* valueName, std::wstring& value) {
    if (key == nullptr || valueName == nullptr) {
        return false;
    }

    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        return false;
    }
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0) {
        return false;
    }

    std::wstring buffer(size / sizeof(wchar_t) + 1, L'\0');
    DWORD readSize = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
    if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()),
                         &readSize) != ERROR_SUCCESS) {
        return false;
    }
    buffer.resize(wcslen(buffer.c_str()));

    if (type == REG_EXPAND_SZ) {
        std::wstring expanded(buffer.size() + MAX_PATH, L'\0');
        const DWORD length = ExpandEnvironmentStringsW(buffer.c_str(), expanded.data(),
                                                       static_cast<DWORD>(expanded.size()));
        if (length > 0 && length <= expanded.size()) {
            expanded.resize(length > 0 ? length - 1 : 0);
            value = std::move(expanded);
            return true;
        }
    }

    value = std::move(buffer);
    return true;
}

// 写入字符串值
inline bool WriteRegistryString(HKEY key, const wchar_t* valueName, const std::wstring& value,
                                DWORD type = REG_SZ) {
    if (key == nullptr || valueName == nullptr) {
        return false;
    }
    const DWORD size = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return RegSetValueExW(key, valueName, 0, type, reinterpret_cast<const BYTE*>(value.c_str()),
                          size) == ERROR_SUCCESS;
}

} // namespace GuardDog