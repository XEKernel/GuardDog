#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace GuardDog {

struct Config;

// 文件处置结果。用枚举而不是 bool，是因为"删掉了"和"删不掉但已废掉"
// 属于两种不同的成功形态，调用方与日志都需要区分。
enum class DestroyOutcome {
    AlreadyGone,         // 文件本来就不存在（视为已达成目标）
    Deleted,             // 直接删除成功（含解除占用后删除）
    PeHeaderDestroyed,   // 删除失败，但 PE 头已覆写（程序永久无法运行）
    ScheduledForReboot,  // 删除与破坏都失败，已登记重启后删除
    Rejected,            // 未命中黑名单，拒绝处置（防误伤）
    Failed,              // 全部手段失效
};

struct DestroyResult {
    DestroyOutcome outcome = DestroyOutcome::Failed;
    std::wstring path;
    std::wstring detail;  // 补充说明（例如被哪个进程占用）

    bool IsHandled() const {
        return outcome == DestroyOutcome::AlreadyGone || outcome == DestroyOutcome::Deleted ||
               outcome == DestroyOutcome::PeHeaderDestroyed ||
               outcome == DestroyOutcome::ScheduledForReboot;
    }

    std::wstring Describe() const;
};

// 处置授权范围。
// 文件处置不可逆，所以默认只允许处置"自身命中黑名单"的文件；
// 只有在配置里显式打开了"整套软件处置"（remove_whole_directory）时，
// 才允许把授权放宽到"目标软件所在的目录树"。
enum class DisposeScope {
    BlacklistMatch,  // 仅当文件本身命中黑名单（默认，最严格）
    SoftwareTree,    // 调用方已确认整棵目录树属于该黑名单软件
};

// 文件销毁器：三级递进策略。
//
// F1 直接删除 → F2 解除占用后删除 → F3 登记重启删除 + 覆写 PE 头
//
// 为什么最后要破坏 PE 头：流氓软件的常驻组件往往有驱动/守护进程持有文件句柄，
// 使删除长期失败。而只要把 PE 头（前 1KB）清零，Windows 加载器就会报
// "不是有效的 Win32 应用程序"，该程序即永久报废——即使文件还留在磁盘上也无害。
class FileDestroyer {
public:
    // 处置一个文件。内部会再次校验授权范围（纵深防御），未授权直接拒绝。
    static DestroyResult DestroyFile(const Config& config, const std::wstring& path,
                                     DisposeScope scope = DisposeScope::BlacklistMatch);

    // 只覆写 PE 头（不删除文件）。用于"文件还需保留但必须废掉"的场景。
    static bool OverwritePeHeader(const std::wstring& path);

    // 判断是否是可执行映像（PE）。非 PE 文件破坏头部没有意义，也不该动它。
    static bool IsPortableExecutable(const std::wstring& path);

    // 找出正在占用该文件的进程 PID（Restart Manager，官方接口）
    static std::vector<DWORD> FindProcessesLockingFile(const std::wstring& path);
};

} // namespace GuardDog