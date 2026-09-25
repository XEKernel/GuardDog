#pragma once

#include <windows.h>

#include <string>

#include "Core/ScopeHandle.h"

namespace GuardDog {

// 以隐藏方式运行命令行工具并等待结束。
//
// 为什么不用 system() / _wsystem()：服务进程没有控制台，但 system() 会在用户会话里
// 弹出黑色控制台窗口，用户能明显察觉"后台有东西在跑"。统一走
// CreateProcessW + CREATE_NO_WINDOW，并用 STARTF_USESHOWWINDOW/SW_HIDE 双保险。
//
// 返回 true 表示子进程已结束（此时 exitCode 有效）。
inline bool RunHiddenProcess(const std::wstring& commandLine, DWORD timeoutMs, DWORD& exitCode) {
    std::wstring mutableCommand = commandLine;  // CreateProcessW 可能就地修改命令行缓冲区

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo{};
    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startupInfo, &processInfo)) {
        return false;
    }

    ScopeHandle process(processInfo.hProcess);
    ScopeHandle thread(processInfo.hThread);

    if (WaitForSingleObject(process.Get(), timeoutMs) != WAIT_OBJECT_0) {
        return false;  // 超时：不等待也不强杀，交由调用方记录
    }

    return GetExitCodeProcess(process.Get(), &exitCode) != FALSE;
}

// 只关心"是否以 0 退出"的简化版本
inline bool RunHiddenCommand(const std::wstring& commandLine, DWORD timeoutMs = 15000) {
    DWORD exitCode = 1;
    return RunHiddenProcess(commandLine, timeoutMs, exitCode) && exitCode == 0;
}

} // namespace GuardDog