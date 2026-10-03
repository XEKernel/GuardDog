#pragma once

#include <windows.h>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "Core/ComPtr.h"

// COM 接口的完整定义在 wbemidl.h；这里只做前向声明，
// 避免把整套 WMI 头文件传播给每个包含 WmiMonitor.h 的翻译单元。
struct IWbemLocator;
struct IWbemObjectSink;
struct IWbemServices;

namespace GuardDog {

// WMI 回调的共享状态，定义在 .cpp（这里只前向声明）。
//
// WMI 会从自己的线程池调用 sink 的 Indicate，而 CancelAsyncCall 取消订阅时
// 并不会等待在途回调返回。若回调直接触碰 WmiMonitor 实例，一旦本对象（或其
// 所在作用域）先被销毁，就会 use-after-free。把回调与运行标志放进这个由
// sink 与 WmiMonitor 共同持有的 shared_ptr，回调便只依赖该状态，不再依赖
// WmiMonitor 实例本身。
//
// 注意：该类型必须能在头文件里按名引用（m_state 成员），因此留在 GuardDog
// 命名空间中，不能放进 .cpp 的匿名命名空间。
struct WmiMonitorState;

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

    bool IsRunning() const;

    // 订阅异常中断（例如 WMI 服务重启）时置位，由主循环决定何时重建订阅
    bool NeedsReconnect() const;
    void ClearReconnectFlag();

private:
    ComPtr<IWbemLocator> m_locator;
    ComPtr<IWbemServices> m_service;
    ComPtr<IWbemObjectSink> m_sink;

    // 与 sink 共享的回调/运行状态；sink 持有一份，因此即使本对象先销毁，
    // 在途回调操作的状态仍然有效。
    std::shared_ptr<WmiMonitorState> m_state;

    bool m_comInitialized = false;
};

} // namespace GuardDog