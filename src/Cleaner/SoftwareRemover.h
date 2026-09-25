#pragma once

#include <string>

namespace GuardDog {

struct Config;

struct SoftwareDisposalResult {
    int filesScanned = 0;    // 检查过的可执行载体数量
    int filesDisposed = 0;   // 已删除或已破坏的文件数
    int filesFailed = 0;     // 处置失败数
    int filesSkipped = 0;    // 因未获授权而跳过的文件数
    int directoriesRemoved = 0;

    std::wstring Describe() const;
};

// 软件整体处置（模块 F 的扩展）。
//
// 只删除"被捕获的那一个 exe"是不够的：流氓软件是一个目录，
// 里面通常还有守护进程、插件 DLL、升级器、卸载器。删掉一个 exe，其余的仍然能跑，
// 甚至卸载器还能把被删的主程序重新装回来——软件只废了一半。
//
// 因此这里以目标所在目录为根，把目录树里的可执行载体逐个处置（删除；删不掉就毁 PE 头）。
// 数据文件（配置、日志、缓存）刻意不动：一来它们无法执行，二来误删用户数据的代价太高。
class SoftwareRemover {
public:
    // 处置 imagePath 所属的整个软件目录
    static SoftwareDisposalResult RemoveSoftware(const Config& config,
                                                 const std::wstring& imagePath);

    // 处置一个明确的目录（用于已安装程序的 InstallLocation）。
    // 注意方法名刻意避开 "RemoveDirectory"：Windows 头文件里有
    // #define RemoveDirectory RemoveDirectoryW，同名成员会被宏替换掉。
    static SoftwareDisposalResult DisposeDirectory(const Config& config,
                                                   const std::wstring& directory);
};

} // namespace GuardDog