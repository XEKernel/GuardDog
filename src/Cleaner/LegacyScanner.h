#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace GuardDog {

struct Config;

// 存量扫描的一次性结果。
//
// 注意：这里只负责"发现"，不负责"处置"——处置由调用方决定，
// 因为扫描可能在"只读预检"场景下被调用（用户想先看看有什么，再决定动不动手）。
struct LegacyScanResult {
    struct Hit {
        std::wstring path;        // 命中的文件路径，或进程映像路径
        DWORD processId = 0;      // 非 0 表示这是运行中的进程
        std::wstring source;      // 来源：已安装程序 / 运行进程 / 安装目录
        std::wstring detail;      // 补充信息（软件名、卸载命令等）
    };

    std::vector<Hit> hits;

    int installedChecked = 0;    // 检查过的已安装程序条目数
    int installedMatched = 0;    // 命中的已安装程序数
    int processesChecked = 0;    // 检查过的运行中进程数
    int directoriesChecked = 0;  // 检查过的安装目录数
    int filesChecked = 0;        // 检查过的目录内文件数

    std::wstring Describe() const;
};

// 存量扫描器（模块 E）：清理"服务启动前就已经存在的"流氓软件。
//
// 三条路径：
//   E1 已安装程序：遍历 Uninstall 注册表键，匹配卸载命令与安装目录
//   E2 运行中进程：全量进程快照，命中即报告
//   E3 常见安装目录：只扫一层子目录内的可执行文件，避免全盘遍历
class LegacyScanner {
public:
    // 执行一次存量扫描（只读）。返回发现的黑名单目标，由调用方决定如何处置。
    static LegacyScanResult Scan(const Config& config);
};

} // namespace GuardDog