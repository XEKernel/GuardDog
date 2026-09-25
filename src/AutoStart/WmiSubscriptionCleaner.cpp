#include "AutoStart/AutoStartScanner.h"

#include "Core/ComPtr.h"
#include "Core/ConfigManager.h"
#include "Core/Logger.h"

#include <wbemidl.h>

#include <cwctype>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")

namespace GuardDog {
namespace Cleaners {

namespace {

// 命中的消费者实例
struct ConsumerVictim {
    std::wstring relativePath;  // 形如 CommandLineEventConsumer.Name="X"
    std::wstring kind;
    std::wstring detail;
};

// 绑定关系：把消费者与过滤器关联起来
struct BindingInfo {
    std::wstring relativePath;
    std::wstring consumer;
    std::wstring filter;
};

bool ReadString(IWbemClassObject* object, const wchar_t* name, std::wstring& value) {
    VARIANT variant;
    VariantInit(&variant);

    bool ok = false;
    if (SUCCEEDED(object->Get(name, 0, &variant, nullptr, nullptr)) && variant.vt == VT_BSTR &&
        variant.bstrVal != nullptr) {
        value.assign(variant.bstrVal, SysStringLen(variant.bstrVal));
        ok = true;
    }

    VariantClear(&variant);
    return ok;
}

std::wstring GetRelativePath(IWbemClassObject* object) {
    std::wstring value;
    ReadString(object, L"__RELPATH", value);
    return value;
}

// 同步查询并取回全部实例（订阅表通常只有几十条，一次性取回最简单可靠）
std::vector<ComPtr<IWbemClassObject>> QueryInstances(IWbemServices* service,
                                                     const std::wstring& wql) {
    std::vector<ComPtr<IWbemClassObject>> instances;

    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(wql.c_str());

    ComPtr<IEnumWbemClassObject> enumerator;
    const HRESULT hr = service->ExecQuery(language, query,
                                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                          nullptr, enumerator.Put());
    SysFreeString(language);
    SysFreeString(query);

    if (FAILED(hr)) {
        return instances;
    }

    for (;;) {
        IWbemClassObject* rawObjects[8] = {};
        ULONG returned = 0;
        const HRESULT nextResult =
            enumerator->Next(5000, _countof(rawObjects), rawObjects, &returned);
        if (FAILED(nextResult) || returned == 0) {
            break;
        }

        for (ULONG i = 0; i < returned; ++i) {
            instances.emplace_back(rawObjects[i]);  // ComPtr 接管，无需手动 Release
        }
    }

    return instances;
}

bool DeleteInstance(IWbemServices* service, const std::wstring& relativePath) {
    if (relativePath.empty()) {
        return false;
    }

    BSTR path = SysAllocString(relativePath.c_str());
    const HRESULT hr = service->DeleteInstance(path, 0, nullptr, nullptr);
    SysFreeString(path);

    if (FAILED(hr)) {
        GD_LOG_ERROR(L"删除 WMI 订阅实例失败：%s（0x%08X）", relativePath.c_str(), hr);
        return false;
    }
    return true;
}

// 脚本内容里出现目标标识（进程名或完整路径）就算命中。
// ActiveScript 型消费者没有命令行可以精确解析，只能做这种宽松匹配——
// 代价是可能命中"脚本里恰好提到该文件名"的合法订阅，因此只作为第二判据，
// 且原始脚本内容会完整写入备份日志，便于人工核对与恢复。
bool ScriptMentionsTarget(const std::wstring& scriptText, const std::wstring& targetImageName,
                          const std::wstring& targetImagePath) {
    if (scriptText.empty()) {
        return false;
    }

    std::wstring lowerScript = scriptText;
    for (wchar_t& ch : lowerScript) {
        ch = static_cast<wchar_t>(towlower(ch));
    }

    const auto contains = [&lowerScript](const std::wstring& needle) {
        if (needle.empty()) {
            return false;
        }
        std::wstring lowerNeedle = needle;
        for (wchar_t& ch : lowerNeedle) {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        return lowerScript.find(lowerNeedle) != std::wstring::npos;
    };

    return contains(targetImagePath) || contains(targetImageName);
}

} // namespace

CleanResult CleanWmiSubscriptions(const Config& config, const AutoStartTarget& target, bool clean) {
    CleanResult result;

    ScopedCom com;
    if (!com.IsUsable()) {
        GD_LOG_WARN(L"COM 不可用，跳过 WMI 永久事件订阅检查");
        return result;
    }

    const HRESULT securityResult =
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(securityResult) && securityResult != RPC_E_TOO_LATE) {
        GD_LOG_WARN(L"CoInitializeSecurity 返回 0x%08X，可能影响订阅清理", securityResult);
    }

    ComPtr<IWbemLocator> locator;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                                reinterpret_cast<void**>(locator.Put())))) {
        GD_LOG_WARN(L"创建 IWbemLocator 失败，跳过订阅清理");
        return result;
    }

    BSTR nameSpace = SysAllocString(L"ROOT\\subscription");
    ComPtr<IWbemServices> service;
    const HRESULT connectResult =
        locator->ConnectServer(nameSpace, nullptr, nullptr, nullptr, 0, nullptr, nullptr,
                               reinterpret_cast<IWbemServices**>(service.Put()));
    SysFreeString(nameSpace);
    if (FAILED(connectResult)) {
        GD_LOG_WARN(L"连接 ROOT\\subscription 失败（0x%08X），跳过订阅清理", connectResult);
        return result;
    }

    CoSetProxyBlanket(service.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    // ---- 第一步：找出所有指向目标的消费者 ----
    std::vector<ConsumerVictim> victims;

    for (const ComPtr<IWbemClassObject>& instance :
         QueryInstances(service.Get(), L"SELECT * FROM CommandLineEventConsumer")) {
        ++result.scanned;

        std::wstring name;
        std::wstring commandLineTemplate;
        ReadString(instance.Get(), L"Name", name);
        ReadString(instance.Get(), L"CommandLineTemplate", commandLineTemplate);

        if (!IsTargetCommand(config, commandLineTemplate)) {
            continue;
        }

        ++result.matched;
        victims.push_back(ConsumerVictim{GetRelativePath(instance.Get()), L"CommandLineEventConsumer",
                                         name + L" → " + commandLineTemplate});
    }

    for (const ComPtr<IWbemClassObject>& instance :
         QueryInstances(service.Get(), L"SELECT * FROM ActiveScriptEventConsumer")) {
        ++result.scanned;

        std::wstring name;
        std::wstring scriptText;
        std::wstring scriptFileName;
        ReadString(instance.Get(), L"Name", name);
        ReadString(instance.Get(), L"ScriptText", scriptText);
        ReadString(instance.Get(), L"ScriptFileName", scriptFileName);

        const bool hit = IsTargetCommand(config, scriptFileName) ||
                         ScriptMentionsTarget(scriptText, target.imageName, target.imagePath);
        if (!hit) {
            continue;
        }

        ++result.matched;
        victims.push_back(ConsumerVictim{GetRelativePath(instance.Get()),
                                         L"ActiveScriptEventConsumer",
                                         name + L"（脚本内容命中）"});
    }

    if (victims.empty()) {
        return result;
    }

    // ---- 第二步：记录并（在需要时）清除 ----
    for (const ConsumerVictim& victim : victims) {
        ReportAutoStartHit(L"WMI 永久事件订阅", victim.relativePath, victim.detail, clean);
    }

    if (!clean) {
        return result;
    }

    // 先把绑定关系全部取回：删除顺序必须是 绑定 → 消费者 → 过滤器，
    // 反过来删会留下指向已删除对象的悬空绑定，并让订阅清理不彻底。
    std::vector<BindingInfo> bindings;
    for (const ComPtr<IWbemClassObject>& instance :
         QueryInstances(service.Get(), L"SELECT * FROM __FilterToConsumerBinding")) {
        BindingInfo info;
        info.relativePath = GetRelativePath(instance.Get());
        ReadString(instance.Get(), L"Consumer", info.consumer);
        ReadString(instance.Get(), L"Filter", info.filter);
        bindings.push_back(std::move(info));
    }

    // 过滤器的引用计数：只有不再被任何绑定引用的过滤器才可以删除，
    // 否则会破坏其他（合法的）订阅。
    std::vector<std::pair<std::wstring, int>> filterRefCounts;
    const auto addFilterRef = [&filterRefCounts](const std::wstring& filter) {
        for (auto& entry : filterRefCounts) {
            if (entry.first == filter) {
                ++entry.second;
                return;
            }
        }
        filterRefCounts.emplace_back(filter, 1);
    };

    for (const BindingInfo& binding : bindings) {
        addFilterRef(binding.filter);
    }

    int removedCount = 0;
    for (const ConsumerVictim& victim : victims) {
        for (const BindingInfo& binding : bindings) {
            if (binding.consumer != victim.relativePath) {
                continue;
            }

            if (DeleteInstance(service.Get(), binding.relativePath)) {
                GD_LOG_INFO(L"已删除订阅绑定：%s", binding.relativePath.c_str());
            }

            // 该过滤器少了一个引用者
            for (auto& entry : filterRefCounts) {
                if (entry.first == binding.filter && entry.second > 0) {
                    --entry.second;
                    break;
                }
            }
        }

        if (DeleteInstance(service.Get(), victim.relativePath)) {
            GD_LOG_INFO(L"已删除订阅消费者：%s", victim.relativePath.c_str());
            ++removedCount;
        }
    }

    // 清理不再被引用的过滤器
    for (const auto& entry : filterRefCounts) {
        if (entry.second > 0 || entry.first.empty()) {
            continue;
        }
        if (DeleteInstance(service.Get(), entry.first)) {
            GD_LOG_INFO(L"已删除订阅过滤器：%s", entry.first.c_str());
        }
    }

    result.removed = removedCount;
    result.failed = result.matched - removedCount;
    return result;
}

} // namespace Cleaners
} // namespace GuardDog