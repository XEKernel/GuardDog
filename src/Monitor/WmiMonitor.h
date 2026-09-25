#pragma once

#include <windows.h>

#include <atomic>
#include <functional>
#include <string>

#include "Core/ComPtr.h"

// COM 接口的完整定义在 wbemidl.h；这里只做前向声明，
// 避免把整套 WMI 头文件传播给每个包含 WmiMonitor.h 的翻译单元。
struct IWbemLocator;
struct IWbemObjectSink;
struct IWbemServices;

namespace GuardDog {

class ProcessStartSink;

// 进程创建事件的即时监控（主方案）。
//
// 相比轮询，WMI 事件在进程刚创建时就会回调（通常几十毫秒内），
// 使 GuardDog 能在流氓软件完成自启动注册、拉起守护进程之前就冻住它。
// 但它并非绝对可靠（WMI 服务重启、系统高负载都可能丢事件），因此始终保留轮询兜底。
class WmiMonitor {
public:
    using ProcessCallback = std::function<void(DWORD processId, const std::wstring& processName)>;

    // 构造与析构都在 .cpp 中定义：
    // 它们需要销毁 ComPtr 成员，而 COM 接口的完整定义（wbemidl.h）不希望泄漏到本头文件
    WmiMonitor();
    ~WmiMonitor();
    WmiMonitor(const WmiMonitor&) = delete;
    WmiMonitor& operator=(const WmiMonitor&) = delete;

    // 建立 Win32_ProcessStartTrace 异步订阅。返回 S_OK 表示订阅已被 WMI 受理。
    HRESULT Start(const ProcessCallback& callback);
    void Stop();

    bool IsRunning() const { return m_running.load(); }

    // 订阅异常中断（例如 WMI 服务重启）时置位，由主循环决定何时重建订阅
    bool NeedsReconnect() const { return m_needsReconnect.load(); }
    void ClearReconnectFlag() { m_needsReconnect.store(false); }

private:
    friend class ProcessStartSink;

    void OnProcessStarted(DWORD processId, const std::wstring& processName);
    void OnSubscriptionBroken(HRESULT result);

    ComPtr<IWbemLocator> m_locator;
    ComPtr<IWbemServices> m_service;
    ComPtr<IWbemObjectSink> m_sink;
    ProcessCallback m_callback;

    bool m_comInitialized = false;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_needsReconnect{false};
};

} // namespace GuardDog