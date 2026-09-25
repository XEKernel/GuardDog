#pragma once

#include <windows.h>

namespace GuardDog {

// RAII 句柄封装。
// 服务代码里 HANDLE / SC_HANDLE 密集出现，任何一个中途 return 或提前失败分支
// 都可能泄漏句柄（服务是长驻进程，泄漏会持续累积）。统一用这个类兜底，
// 让"打开即持有、离开作用域即关闭"成为默认行为。
//
// SC_HANDLE 本质就是 HANDLE，但要用 CloseServiceHandle 关闭，
// 因此提供带自定义关闭器的 Reset 重载（模板形式，避免函数指针签名不匹配）。
class ScopeHandle {
public:
    ScopeHandle() noexcept = default;
    explicit ScopeHandle(HANDLE handle) noexcept : m_handle(handle) {}

    ~ScopeHandle() { Reset(); }

    ScopeHandle(const ScopeHandle&) = delete;
    ScopeHandle& operator=(const ScopeHandle&) = delete;

    ScopeHandle(ScopeHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    ScopeHandle& operator=(ScopeHandle&& other) noexcept {
        if (this != &other) {
            Reset(other.m_handle);
            other.m_handle = nullptr;
        }
        return *this;
    }

    bool IsValid() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    HANDLE Get() const noexcept { return m_handle; }

    // 取地址用于接收 API 的出参句柄（如 OpenProcessToken 的第二个参数）。
    // 先释放旧句柄，避免新值直接把旧值覆盖掉造成泄漏。
    HANDLE* Put() noexcept {
        Reset();
        return &m_handle;
    }

    // 交还所有权：调用方负责关闭
    HANDLE Release() noexcept {
        HANDLE handle = m_handle;
        m_handle = nullptr;
        return handle;
    }

    void Reset(HANDLE handle = nullptr) noexcept {
        if (IsValid()) {
            CloseHandle(m_handle);
        }
        m_handle = handle;
    }

    // closer 可为 CloseServiceHandle、RegCloseKey 等任意可调用体
    template <typename Closer>
    void Reset(HANDLE handle, Closer closer) noexcept {
        if (IsValid()) {
            closer(m_handle);
        }
        m_handle = handle;
    }

private:
    HANDLE m_handle = nullptr;
};

} // namespace GuardDog