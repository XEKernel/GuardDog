#pragma once

#include <windows.h>

// WIN32_LEAN_AND_MEAN 会排除 COM 相关声明，而 ScopedCom 需要 CoInitializeEx/CoUninitialize
#include <objbase.h>

#include <string>

namespace GuardDog {

struct Config;

// 断根目标：描述"要清理哪个软件的踪迹"。
struct AutoStartTarget {
    std::wstring imagePath;  // 被处置进程的完整路径（可能为空）
    std::wstring imageName;  // 进程名，例如 test.exe
    std::wstring ruleName;   // 命中的黑名单规则名，仅用于日志

    std::wstring Describe() const;
};

// 单个自启动位置的清理统计
struct CleanResult {
    int scanned = 0;  // 检查过的条目数
    int matched = 0;  // 命中目标的条目数
    int removed = 0;  // 成功清除数
    int failed = 0;   // 清除失败数

    void Accumulate(const CleanResult& other);
    std::wstring Describe() const;
};

// ---------------------------------------------------------------------------
// 公共工具
// ---------------------------------------------------------------------------

// 从命令行中提取可执行文件路径。
// 自启动项里存的是命令行而不是纯路径，形态五花八门：
//   "C:\Program Files\X\a.exe" /silent
//   C:\X\a.exe -autorun
//   %ProgramFiles%\X\a.exe
// 不解析出真正的 exe 路径，就没法与黑名单规则比较。
std::wstring ExtractExecutablePath(const std::wstring& commandLine);

// 判断一段命令行（或路径）是否指向需要断根的目标。
// 内部统一走 Matcher，因此黑名单的四个维度、白名单优先都自动生效。
bool IsTargetCommand(const Config& config, const std::wstring& commandLine);

// 读取文本文件为宽字符串，自动识别 UTF-16LE（BOM）与 UTF-8/本地编码。
// 计划任务的 XML 定义文件是 UTF-16LE，而用户自制的脚本多半是 UTF-8。
bool ReadTextFileWide(const std::wstring& path, std::wstring& content);

// 删除文件（先清掉只读/隐藏属性——流氓软件常靠只读属性逃避删除）
bool DeleteFileForce(const std::wstring& path);

// 取路径的父目录（末尾不带分隔符）；无父目录时返回空串
std::wstring ParentDirectoryOf(const std::wstring& path);

// 统一的"命中自启动项"上报：
//   clean = true  → warn 日志 + 原始值备份（要动手了，必须留痕）
//   clean = false → 只写 debug（预检与清除后复查都走这条路，避免刷屏与重复备份）
void ReportAutoStartHit(const wchar_t* category, const std::wstring& item,
                        const std::wstring& detail, bool clean);

// 作用域内保证 COM 可用。
// 解析快捷方式、访问 WMI 订阅都需要 COM，而清理流程可能跑在尚未初始化 COM 的线程上；
// 内部做配对初始化（成功初始化才配对反初始化，RPC_E_CHANGED_MODE 则只标记可用）。
class ScopedCom {
public:
    ScopedCom() noexcept {
        const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        m_usable = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
        m_needsUninitialize = SUCCEEDED(hr);
    }

    ~ScopedCom() {
        if (m_needsUninitialize) {
            CoUninitialize();
        }
    }

    ScopedCom(const ScopedCom&) = delete;
    ScopedCom& operator=(const ScopedCom&) = delete;

    bool IsUsable() const noexcept { return m_usable; }

private:
    bool m_usable = false;
    bool m_needsUninitialize = false;
};

} // namespace GuardDog