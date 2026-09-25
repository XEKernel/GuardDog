#pragma once

#include <windows.h>

#include <functional>
#include <string>

namespace GuardDog {

struct Config;

// 轮询兜底扫描。
// WMI 事件在系统高负载时可能延迟甚至丢失，所以必须保留一条不依赖 WMI 的发现路径：
// 用 CreateToolhelp32Snapshot 定期遍历全部进程，命中黑名单就回调。
//
// 计时放在内部（而不是让调用方每次判断"到点了没"），
// 这样主循环可以用固定节拍驱动，轮询间隔由配置单独控制。
class ProcessPoller {
public:
    using ProcessCallback = std::function<void(DWORD processId, const std::wstring& imagePath)>;

    // 到期才扫描
    void PollIfDue(const Config& config, const ProcessCallback& callback);

    // 忽略间隔立即扫描一次（服务启动时检查"已经在运行的"目标）
    void ScanNow(const Config& config, const ProcessCallback& callback);

    // 配置热重载后调用，让新的轮询间隔立即生效
    void Reset() { m_lastScanTick = 0; }

    // 上一次扫描发现的命中数量（诊断/日志用）
    size_t GetLastMatchedCount() const { return m_lastMatchedCount; }

private:
    void Scan(const Config& config, const ProcessCallback& callback);

    ULONGLONG m_lastScanTick = 0;
    size_t m_lastMatchedCount = 0;
};

} // namespace GuardDog