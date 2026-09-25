#pragma once

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

namespace GuardDog {

// 命名管道命令服务端（模块 I 的服务侧）。
//
// 协议刻意做成"单条纯文本消息"（UTF-16）：请求 "CMD|参数1|参数2"，
// 响应 "OK|数据" 或 "ERR|原因"。这样用 PowerShell 也能手工发命令验证，
// 排查问题时不必先写一个客户端。
class IpcServer {
public:
    using CommandHandler = std::function<std::wstring(
        const std::wstring& command, const std::vector<std::wstring>& arguments)>;

    static IpcServer& Instance();

    // 启动监听线程。handler 会在监听线程上被调用，不要在其中做长耗时操作
    bool Start(CommandHandler handler);
    void Stop();
    bool IsRunning() const { return m_thread != nullptr; }

private:
    IpcServer() = default;
    ~IpcServer();
    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    static DWORD WINAPI ThreadEntry(LPVOID parameter);
    void Run();
    void HandleClient(HANDLE pipe);

    CommandHandler m_handler;
    HANDLE m_thread = nullptr;
    HANDLE m_stopEvent = nullptr;
};

// 供托盘 UI 使用的客户端
class IpcClient {
public:
    // 发送一条命令并等待响应；失败返回 false 并填充 error
    static bool Send(const std::wstring& request, std::wstring& response, DWORD timeoutMs = 5000);
};

} // namespace GuardDog