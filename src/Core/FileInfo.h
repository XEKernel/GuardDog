#pragma once

#include <string>

namespace GuardDog {

// 文件身份信息：黑名单的"签名者""哈希"两个维度都依赖它。
// 这两项计算成本都不低（哈希要读全文件、签名要解 ASN.1 并做策略校验），
// 因此调用方必须按需调用并自行缓存（见 Matcher.cpp 的 FileIdentityCache）。

// 计算文件 SHA-256，输出小写十六进制字符串；失败返回 false
bool ComputeFileSha256(const std::wstring& path, std::wstring& hexDigest);

// 获取签名者显示名（证书 Subject 的 CN，例如 "Microsoft Corporation"）。
// 只有签名通过 WinVerifyTrust 策略校验时才返回 true——
// 只提取"签名结构里的名字"而不校验，等于让流氓软件自己给自己发证书冒充大厂。
bool GetFileSignerName(const std::wstring& path, std::wstring& signerName);

// 归一化哈希写法：去空白、转小写、去掉 "sha256:" 前缀。
// 让用户在配置里写 sha256:ABC 或 ABC 都能命中
std::wstring NormalizeHash(const std::wstring& text);

} // namespace GuardDog