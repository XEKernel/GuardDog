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

// 服务定义。
// 把"装哪个服务"参数化，让主服务与看门狗服务共用同一套安装/卸载实现——
// 否则两份几乎相同的安装代码很容易在后续修改中走偏（例如只给其中一个补了恢复策略）。
struct ServiceDefinition {
    const wchar_t* name = nullptr;
    const wchar_t* displayName = nullptr;
    const wchar_t* description = nullptr;
    bool autoStart = true;
    bool withFailureActions = true;  // 是否写入"失败后 5 秒重启"恢复策略
};

// 主服务定义
const ServiceDefinition& MainServiceDefinition();
// 看门狗服务定义
const ServiceDefinition& WatchdogServiceDefinition();

// 服务安装器。
// 之所以用 API 而不是拼 sc.exe 命令行：命令行要处理引号转义与输出解析，
// 容易出现"看起来成功实际失败"的假象；API 能拿到准确的 Win32 错误码。
class ServiceInstaller {
public:
    // 注册服务 + 设置恢复策略 + 尝试启动。返回 ServiceInstallerExitCode
    static int Install(const ServiceDefinition& definition);

    // 停止并删除服务。返回 ServiceInstallerExitCode
    static int Uninstall(const ServiceDefinition& definition);

    // 当前进程的 exe 完整路径（失败返回空串）
    static std::wstring GetExecutablePath();

private:
    static bool IsElevated();
};

} // namespace GuardDog