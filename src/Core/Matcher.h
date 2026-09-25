#pragma once

#include <string>
#include <vector>

namespace GuardDog {

struct Config;

// 命中的维度。既用于日志说明"凭什么判它是流氓软件"，
// 也用于后续按维度决定处置力度（例如仅签名者命中时可以先提示而不直接删除）。
enum class MatchDimension {
    None = 0,
    ProcessName,
    Path,
    Signer,
    Hash,
};

struct MatchResult {
    bool matched = false;      // 命中黑名单
    bool whitelisted = false;  // 命中白名单（优先级高于黑名单）
    std::wstring ruleName;     // 命中的黑名单规则名
    std::vector<MatchDimension> dimensions;
    std::vector<std::wstring> details;  // 与 dimensions 一一对应的命中值

    std::wstring Describe() const;
};

// 匹配引擎。
// 白名单优先是硬规则：任何处置动作前都要先过这里，
// 命中白名单的目标一律放行，防止把系统关键进程或用户自己的软件误杀。
class Matcher {
public:
    // 综合判定（白名单 → 黑名单）
    static MatchResult Evaluate(const Config& config, const std::wstring& imagePath);

    // 危险操作的强制校验入口：返回 true 才允许删除 / 覆写 / 禁用
    static bool IsInBlacklist(const Config& config, const std::wstring& imagePath);

    // 轻量预筛：只比较进程名与路径两个维度，不触发签名/哈希计算。
    // 供 WMI 回调线程使用——系统每秒会创建几十个进程，若不加过滤全部入队，
    // 队列会被无关进程占满，真正的目标反而可能被挤掉；
    // 而签名与哈希代价太高，不适合放在 COM 回调线程上做，那两类目标交给轮询兜底。
    static bool QuickMatchNameOrPath(const Config& config, const std::wstring& nameOrPath);

    // 通配符匹配：* 匹配任意长度、? 匹配单字符，大小写不敏感（Windows 语义）
    static bool WildcardMatch(const std::wstring& pattern, const std::wstring& text);

    // 路径规则匹配：支持通配符全匹配，也支持"目录前缀"写法
    static bool PathRuleMatch(const std::wstring& pattern, const std::wstring& path);

    static std::wstring FileNameOf(const std::wstring& path);

    static const wchar_t* DimensionName(MatchDimension dimension);

    // 配置热重载后调用：文件身份（签名/哈希）结论可能与新规则集不再对应
    static void ClearIdentityCache();

private:
    static bool MatchStringList(const std::vector<std::wstring>& rules, const std::wstring& value,
                                bool usePathRule, MatchDimension dimension, MatchResult& result);

    // 判断配置里是否存在某个"昂贵维度"的规则：
    // 没有的话就完全不去算签名/哈希，避免对每个进程做几十 MB 的文件读取
    static bool ConfigUsesSigner(const Config& config);
    static bool ConfigUsesHash(const Config& config);
};

} // namespace GuardDog