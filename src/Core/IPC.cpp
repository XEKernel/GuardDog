#include "Core/IPC.h"

#include "Core/Constants.h"
#include "Core/Logger.h"
#include "Core/ScopeHandle.h"

#include <algorithm>
#include <sddl.h>  // ConvertStringSecurityDescriptorToSecurityDescriptorW（管道访问控制）

namespace GuardDog {

namespace {

constexpr DWORD kConnectTimeoutMs = 5000;
constexpr DWORD kIoTimeoutMs = 5000;
constexpr DWORD kMaxMessageChars = 4096;

// 管道名放在沙箱外可访问的命名空间下（UI 以普通用户身份运行，服务以 LocalSystem 运行）。
// 安全性由管道创建时的安全属性与"只允许同机连接"共同保证：
// 客户端能发的最危险命令是"临时放行"与"触发一次只读扫描"，都不会造成破坏。
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\GuardDogIPC";

} // namespace

IpcServer& IpcServer::Instance() {
    static IpcServer instance;
    return instance;
}

IpcServer::~IpcServer() {
    Stop();
}

bool IpcServer::Start(CommandHandler handler) {
    if (m_thread != nullptr) {
        return true;
    }

    m_handler = std::move(handler);

    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (m_stopEvent == nullptr) {
        GD_LOG_ERROR(L"IPC：创建停止事件失败（错误 %lu）", GetLastError());
        return false;
    }

    m_thread = CreateThread(nullptr, 0, ThreadEntry, this, 0, nullptr);
    if (m_thread == nullptr) {
        GD_LOG_ERROR(L"IPC：创建监听线程失败（错误 %lu）", GetLastError());
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
        return false;
    }

    return true;
}

void IpcServer::Stop() {
    if (m_thread == nullptr) {
        return;
    }

    SetEvent(m_stopEvent);

    // 关键：监听线程可能正阻塞在 ConnectNamedPipe 上。
    // 主动连接一次自己把这次阻塞唤醒，线程随后会看到停止事件并退出——
    // 这比改用重叠 I/O 简单得多，也是命名管道服务端常用的收尾手法。
    HANDLE wakeup = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                0, nullptr);
    if (wakeup != INVALID_HANDLE_VALUE) {
        CloseHandle(wakeup);
    }

    WaitForSingleObject(m_thread, 5000);
    CloseHandle(m_thread);
    m_thread = nullptr;

    CloseHandle(m_stopEvent);
    m_stopEvent = nullptr;
    m_handler = nullptr;

    GD_LOG_INFO(L"IPC：命令服务已停止");
}

DWORD WINAPI IpcServer::ThreadEntry(LPVOID parameter) {
    static_cast<IpcServer*>(parameter)->Run();
    return 0;
}

void IpcServer::Run() {
    GD_LOG_INFO(L"IPC：命令服务已启动（管道 %s）", kPipeName);

    for (;;) {
        if (WaitForSingleObject(m_stopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        // 管道安全描述符：CreateNamedPipeW 的默认描述符允许**任何本机进程**连接，
        // 而管道能执行"临时放行"动作——那等于让任意程序给自己开绿灯。
        // 这里把访问权限收紧到 SYSTEM、本机管理员与交互登录用户（前端属于后者）：
        //    SY = LocalSystem，BA = Builtin Administrators，IU = 交互登录用户
        // PIPE_REJECT_REMOTE_CLIENTS 另外拒绝一切远程连接；
        // FILE_FLAG_FIRST_PIPE_INSTANCE 则保证本服务是管道的首位创建者——
        // 否则其他进程可以抢先建同名管道冒充 GuardDog 服务，前端就会连到假的上去。
        SECURITY_ATTRIBUTES securityAttributes{};
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1, &securityDescriptor,
                nullptr)) {
            securityAttributes.nLength = sizeof(securityAttributes);
            securityAttributes.lpSecurityDescriptor = securityDescriptor;
        }

        ScopeHandle pipe;
        pipe.Reset(CreateNamedPipeW(
            kPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,  // 单实例：UI 只有一个，串行处理足够
            kMaxMessageChars * sizeof(wchar_t), kMaxMessageChars * sizeof(wchar_t), kIoTimeoutMs,
            securityDescriptor != nullptr ? &securityAttributes : nullptr));

        // CreateNamedPipeW 已复制描述符内容，这里可以立即释放
        if (securityDescriptor != nullptr) {
            LocalFree(securityDescriptor);
        }
        if (!pipe.IsValid()) {
            GD_LOG_WARN(L"IPC：创建管道失败（错误 %lu），稍后重试", GetLastError());
            Sleep(1000);
            continue;
        }

        const BOOL connected = ConnectNamedPipe(pipe.Get(), nullptr);
        const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();

        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            // 被停止信号唤醒时会走到这里（客户端连接后立刻断开）
            Sleep(100);
            continue;
        }

        if (WaitForSingleObject(m_stopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        HandleClient(pipe.Get());

        FlushFileBuffers(pipe.Get());
        DisconnectNamedPipe(pipe.Get());
    }
}

void IpcServer::HandleClient(HANDLE pipe) {
    wchar_t buffer[kMaxMessageChars] = {};
    DWORD bytesRead = 0;

    if (!ReadFile(pipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, nullptr) ||
        bytesRead < sizeof(wchar_t)) {
        return;
    }
    buffer[bytesRead / sizeof(wchar_t)] = L'\0';

    // 容忍 UTF-16 BOM 与尾部换行：
    // 用 PowerShell / .NET 客户端手工发命令时，这两样几乎必然出现；
    // 不处理的话命令名会变成 "\uFEFFSTATUS\n" 而永远匹配不上，排查起来很费时间。
    std::wstring request(buffer);
    if (!request.empty() && request.front() == L'\uFEFF') {
        request.erase(0, 1);
    }
    while (!request.empty() && (request.back() == L'\r' || request.back() == L'\n' ||
                                request.back() == L' ')) {
        request.pop_back();
    }

    // 解析 "CMD|参数1|参数2"
    std::wstring command;
    std::vector<std::wstring> arguments;

    size_t start = 0;
    bool isFirstToken = true;
    for (;;) {
        const size_t separator = request.find(L'|', start);
        const std::wstring token = request.substr(
            start, separator == std::wstring::npos ? std::wstring::npos : separator - start);
        if (isFirstToken) {
            command = token;
            isFirstToken = false;
        } else {
            arguments.push_back(token);
        }
        if (separator == std::wstring::npos) {
            break;
        }
        start = separator + 1;
    }

    GD_LOG_INFO(L"IPC：收到命令 %s", command.c_str());

    std::wstring response = L"ERR|服务端未注册命令处理器";
    if (m_handler) {
        response = m_handler(command, arguments);
    }

    DWORD bytesWritten = 0;
    WriteFile(pipe, response.c_str(),
              static_cast<DWORD>((response.size() + 1) * sizeof(wchar_t)), &bytesWritten, nullptr);
}

bool IpcClient::Send(const std::wstring& request, std::wstring& response, DWORD timeoutMs) {
    response.clear();

    // 管道可能尚未创建（服务正忙），带重试地等待
    if (!WaitNamedPipeW(kPipeName, timeoutMs)) {
        return false;
    }

    ScopeHandle pipe;
    pipe.Reset(CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0,
                           nullptr));
    if (!pipe.IsValid()) {
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe.Get(), &mode, nullptr, nullptr);

    DWORD bytesWritten = 0;
    if (!WriteFile(pipe.Get(), request.c_str(),
                   static_cast<DWORD>(request.size() * sizeof(wchar_t)), &bytesWritten, nullptr)) {
        return false;
    }

    wchar_t buffer[kMaxMessageChars] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe.Get(), buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, nullptr) ||
        bytesRead < sizeof(wchar_t)) {
        return false;
    }
    buffer[bytesRead / sizeof(wchar_t)] = L'\0';

    response.assign(buffer);
    return true;
}

} // namespace GuardDog