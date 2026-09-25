#pragma once

// 集中存放全局常量（服务标识、数据目录、IPC 名称）。
// 放在公共头里，是为了让服务、安装器、看门狗、UI 引用同一份定义，
// 避免多处硬编码导致改名时漏改（例如改服务名后看门狗找不到主服务）。

namespace GuardDog {
namespace Constants {

// ---- 版本 ----
inline constexpr wchar_t kVersion[]  = L"0.4.0";
inline constexpr wchar_t kBuildStage[] = L"批次4-自启动清理（断根）";

// ---- 主服务标识 ----
inline constexpr wchar_t kServiceName[]        = L"GuardDogService";
inline constexpr wchar_t kServiceDisplayName[] = L"GuardDog 安全防护";
inline constexpr wchar_t kServiceDescription[] =
    L"GuardDog 防流氓软件防护服务：进程监控、自启动项清理、文件处置与复活对抗。";

// ---- 看门狗服务标识（批次 6 使用）----
inline constexpr wchar_t kWatchdogServiceName[]  = L"GuardDogWatchdog";
inline constexpr wchar_t kWatchdogDisplayName[]  = L"GuardDog 看门狗";

// ---- 数据目录 ----
// 固定使用 ProgramData：LocalSystem 服务与各登录用户都能访问，
// 且不受单用户重定向（如 UAC 虚拟化）影响。
inline constexpr wchar_t kProgramDataDir[] = L"C:\\ProgramData\\GuardDog";
inline constexpr wchar_t kConfigFileName[] = L"config.json";
inline constexpr wchar_t kLogDirName[]     = L"logs";
inline constexpr wchar_t kLogFileName[]    = L"guarddog.log";

// ---- IPC（批次 3+ 使用）----
inline constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\GuardDogIPC";

// ---- 日志保留策略 ----
inline constexpr int kLogKeepDays = 30;

} // namespace Constants
} // namespace GuardDog