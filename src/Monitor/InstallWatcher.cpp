#include "Monitor/InstallWatcher.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <set>
#include <vector>

#include "Cleaner/SoftwareRemover.h"
#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"

namespace GuardDog {
namespace {

// 轮询间隔与延迟处置时长
constexpr int kPollIntervalMs = 2000;
// 命中后等多久再清理：安装程序此刻往往正在往目录里写文件，
// 立刻动手会因文件被独占而删不干净，反而留下"装了一半"的残骸
constexpr int kCleanupDelayMs = 4000;

struct PendingCleanup {
    std::wstring directory;
    std::wstring ruleName;
    std::chrono::steady_clock::time_point dueTime;
};

std::set<std::wstring> g_knownDirectories;
std::vector<PendingCleanup> g_pending;
bool g_primed = false;  // 是否已建立基线（首次轮询只记录，不处置）
std::chrono::steady_clock::time_point g_lastPoll{};

bool ContainsIgnoreCase(const std::wstring& text, const std::wstring& needle) {
    if (needle.empty() || text.size() < needle.size()) {
        return false;
    }
    return std::search(text.begin(), text.end(), needle.begin(), needle.end(),
                       [](wchar_t left, wchar_t right) {
                           return towlower(left) == towlower(right);
                       }) != text.end();
}

std::vector<std::wstring> ListSubdirectories(const std::wstring& root) {
    std::vector<std::wstring> result;

    WIN32_FIND_DATAW data{};
    const std::wstring pattern = root + L"\\*";
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return result;
    }

    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }
        result.push_back(root + L"\\" + data.cFileName);
    } while (FindNextFileW(find, &data));

    FindClose(find);
    return result;
}

// 需要监视的安装根目录。
//
// 注意 AppData 的处理：服务运行在 LocalSystem 下，%LOCALAPPDATA% / %APPDATA%
// 展开后指向 SYSTEM 自己的配置目录，看不到真实用户。必须遍历 C:\Users 下的
// 每个用户配置单元，否则"装在用户目录里的软件"这一类会完全漏掉。
std::vector<std::wstring> CollectInstallRoots() {
    std::vector<std::wstring> roots;

    const wchar_t* sharedRoots[] = {
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        L"C:\\ProgramData",
    };
    for (const wchar_t* root : sharedRoots) {
        if (GetFileAttributesW(root) != INVALID_FILE_ATTRIBUTES) {
            roots.push_back(root);
        }
    }

    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(L"C:\\Users\\*", &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                continue;
            }
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
                continue;
            }
            if (_wcsicmp(data.cFileName, L"Public") == 0 ||
                _wcsicmp(data.cFileName, L"Default") == 0 ||
                _wcsicmp(data.cFileName, L"Default User") == 0 ||
                _wcsicmp(data.cFileName, L"All Users") == 0) {
                continue;
            }

            const std::wstring profile = std::wstring(L"C:\\Users\\") + data.cFileName;
            for (const wchar_t* sub : {L"\\AppData\\Local", L"\\AppData\\Roaming"}) {
                const std::wstring path = profile + sub;
                if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    roots.push_back(path);
                }
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }

    return roots;
}

// 判断新建目录是否命中黑名单规则。
//
// 两条判定路径：
//   1) 规则名与目录名互为子串——用户给规则起名"某流氓软件"，安装目录常叫
//      "某流氓软件"或"某流氓软件 5.0"，这种模糊匹配最贴近实际命名习惯；
//   2) 规则的路径模式匹配该目录——例如规则里写了 C:\Program Files\某软件\*。
bool MatchDirectory(const Config& config, const std::wstring& directory,
                    std::wstring& matchedRule) {
    const std::wstring name = Matcher::FileNameOf(directory);

    for (const BlacklistEntry& entry : config.blacklist) {
        if (!entry.enabled) {
            continue;
        }

        if (!entry.name.empty() && (ContainsIgnoreCase(name, entry.name) ||
                                    ContainsIgnoreCase(entry.name, name))) {
            matchedRule = entry.name;
            return true;
        }

        for (const std::wstring& pattern : entry.paths) {
            // 目录本身与"目录下的文件"两种形态都试：
            // 规则通常写成 C:\Program Files\某软件\*，而这里拿到的是目录路径
            if (Matcher::PathRuleMatch(pattern, directory) ||
                Matcher::PathRuleMatch(pattern, directory + L"\\placeholder.exe")) {
                matchedRule = entry.name;
                return true;
            }
        }
    }

    return false;
}

void ProcessDueCleanups(const Config& config) {
    const auto now = std::chrono::steady_clock::now();

    for (auto it = g_pending.begin(); it != g_pending.end();) {
        if (now < it->dueTime) {
            ++it;
            continue;
        }

        const std::wstring directory = it->directory;
        const std::wstring ruleName = it->ruleName;
        it = g_pending.erase(it);

        // 纵深防御：真正动手之前用**当前**配置再校验一次。
        // 待清理队列是几秒前排的，期间配置可能已经热重载（用户改了规则或关掉了开关），
        // 用它当时的结论去删文件是不安全的。
        if (!config.settings.blockInstall) {
            GD_LOG_INFO(L"[安装拦截] 开关已关闭，放弃清理：%s", directory.c_str());
            continue;
        }
        if (GetFileAttributesW(directory.c_str()) == INVALID_FILE_ATTRIBUTES) {
            continue;  // 目录已经被删掉了（用户手工卸载或安装程序自己回滚）
        }

        std::wstring verifyRule;
        if (!MatchDirectory(config, directory, verifyRule)) {
            GD_LOG_WARN(L"[安装拦截] 复查不再命中，放弃清理：%s", directory.c_str());
            continue;
        }

        GD_LOG_WARN(L"[安装拦截] 清理疑似安装目录：%s（命中规则：%s）", directory.c_str(),
                    ruleName.c_str());

        // 安装拦截的语义是"这个目录已被确认属于黑名单软件"——目录名命中了规则，
        // 因此按"整套软件"清理，不受 remove_whole_directory 开关约束。
        // 那个开关约束的是"进程命中后连带的目录处置"（目标目录归属未经验证），
        // 而这里是另一条独立路径：目录身份已经由名称/路径匹配确认。
        // 护栏仍然生效：IsTreeDisposalAllowed 会拒绝盘根与系统关键目录。
        Config effective = config;
        effective.settings.removeWholeDirectory = true;

        const SoftwareDisposalResult result = SoftwareRemover::DisposeDirectory(effective, directory);
        GD_LOG_WARN(L"[安装拦截] 清理完成：%s", result.Describe().c_str());
    }
}

} // namespace

void InstallWatcher::Reset() {
    g_knownDirectories.clear();
    g_pending.clear();
    g_primed = false;
}

void InstallWatcher::Poll(const Config& config) {
    const auto now = std::chrono::steady_clock::now();
    if (g_lastPoll.time_since_epoch().count() != 0 &&
        now - g_lastPoll < std::chrono::milliseconds(kPollIntervalMs)) {
        return;
    }
    g_lastPoll = now;

    // 先处理到期的清理任务，再扫新目录——把"已发现"的先了结，队列不会越积越长
    ProcessDueCleanups(config);

    if (!config.settings.blockInstall) {
        return;  // 开关关闭时不扫描，也不建基线
    }

    for (const std::wstring& root : CollectInstallRoots()) {
        for (const std::wstring& directory : ListSubdirectories(root)) {
            const bool isNew = g_knownDirectories.insert(directory).second;

            // 首次运行只建立基线：磁盘上已有的软件都是"存量"，不能当成本次新装，
            // 否则服务一启动就会把符合规则的现有目录全清一遍。
            // 存量清理由 clean_legacy_on_start 负责，那是另一条经过用户明确授权的路径。
            if (!isNew || !g_primed) {
                continue;
            }

            std::wstring matchedRule;
            if (!MatchDirectory(config, directory, matchedRule)) {
                continue;
            }

            GD_LOG_WARN(L"[安装拦截] 发现疑似新装目标：%s（命中规则：%s），%d 秒后清理",
                        directory.c_str(), matchedRule.c_str(), kCleanupDelayMs / 1000);

            g_pending.push_back(PendingCleanup{directory, matchedRule,
                                               now + std::chrono::milliseconds(kCleanupDelayMs)});
        }
    }

    g_primed = true;
}

} // namespace GuardDog