#pragma once

#include <string>

namespace GuardDog {

// 安装/卸载服务的返回码（直接作为进程退出码）
enum ServiceInstallerExitCode : int {
    kInstallerOk            = 0,
    kInstallerFailed        = 1,
    kInstallerNotElevated   = 2,
    kInstallerOpenScmFailed = 3,
    kInstallerExists        = 4,
    kInstallerCreateFailed  = 5,
    kInstallerDeleteFailed  = 6,
    kInstallerBadUsage      = 7,
};

// 服务安装器。
// 只做三件事：注册服务（含描述与恢复策略）、卸载服务、提供自身 exe 路径。
// 之所以用 API 而不是拼 sc.exe 命令行：命令行要处理引号转义与输出解析，
// 容易出现"看起来成功实际失败"的假象；API 能拿到准确的 Win32 错误码。
class ServiceInstaller {
public:
    // 注册服务 + 设置恢复策略 + 尝试启动。返回 ServiceInstallerExitCode
    static int Install();

    // 停止并删除服务。返回 ServiceInstallerExitCode
    static int Uninstall();

    // 当前进程的 exe 完整路径（失败返回空串）
    static std::wstring GetExecutablePath();

private:
    static bool IsElevated();
};

} // namespace GuardDog