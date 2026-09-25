#include "AutoStart/AutoStartTypes.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <vector>

namespace GuardDog {

namespace {

// 去掉首尾空白与包裹的引号
std::wstring Trim(const std::wstring& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && (text[begin] == L' ' || text[begin] == L'\t' || text[begin] == L'\r' ||
                           text[begin] == L'\n')) {
        ++begin;
    }
    while (end > begin && (text[end - 1] == L' ' || text[end - 1] == L'\t' ||
                           text[end - 1] == L'\r' || text[end - 1] == L'\n')) {
        --end;
    }
    return text.substr(begin, end - begin);
}

} // namespace

std::wstring AutoStartTarget::Describe() const {
    return L"路径=" + (imagePath.empty() ? L"(未知)" : imagePath) +
           L" 进程名=" + (imageName.empty() ? L"(未知)" : imageName) +
           L" 规则=" + (ruleName.empty() ? L"(未记录)" : ruleName);
}

void CleanResult::Accumulate(const CleanResult& other) {
    scanned += other.scanned;
    matched += other.matched;
    removed += other.removed;
    failed += other.failed;
}

std::wstring CleanResult::Describe() const {
    wchar_t buffer[192] = {};
    swprintf_s(buffer, L"检查 %d 项，命中 %d 项，已清除 %d 项，失败 %d 项", scanned, matched,
               removed, failed);
    return std::wstring(buffer);
}

std::wstring ParentDirectoryOf(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos == 0) {
        return std::wstring();
    }
    return path.substr(0, pos);
}

std::wstring ExtractExecutablePath(const std::wstring& commandLine) {
    if (commandLine.empty()) {
        return std::wstring();
    }

    // 先展开环境变量：注册表里的自启动项大量使用 %ProgramFiles% 这类写法
    std::wstring expanded(commandLine.size() + MAX_PATH, L'\0');
    const DWORD length =
        ExpandEnvironmentStringsW(commandLine.c_str(), expanded.data(),
                                  static_cast<DWORD>(expanded.size()));
    if (length > 0 && length <= expanded.size()) {
        expanded.resize(length - 1);
    } else {
        expanded = commandLine;
    }

    const std::wstring text = Trim(expanded);
    if (text.empty()) {
        return std::wstring();
    }

    // 情况一：被引号包裹（最规范）
    if (text.front() == L'"') {
        const size_t closing = text.find(L'"', 1);
        if (closing != std::wstring::npos && closing > 1) {
            return text.substr(1, closing - 1);
        }
        return text.substr(1);  // 引号没闭合，退化为取引号后的全部
    }

    // 情况二：无引号但含 .exe —— 取到 ".exe" 为止。
    // 这样即使路径里有空格（C:\Program Files\X\a.exe -silent）也能正确切分。
    const std::wstring lower = [&text]() {
        std::wstring result = text;
        for (wchar_t& ch : result) {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        return result;
    }();
    const size_t exePos = lower.find(L".exe");
    if (exePos != std::wstring::npos) {
        return text.substr(0, exePos + 4);
    }

    // 情况三：既无引号也无 .exe（例如 rundll32 之类），取第一个空格前的部分
    const size_t spacePos = text.find(L' ');
    if (spacePos != std::wstring::npos) {
        return text.substr(0, spacePos);
    }

    return text;
}

bool IsTargetCommand(const Config& config, const std::wstring& commandLine) {
    if (commandLine.empty()) {
        return false;
    }

    const std::wstring executablePath = ExtractExecutablePath(commandLine);
    const std::wstring candidate = executablePath.empty() ? commandLine : executablePath;

    // 用统一的匹配引擎判定：这样"进程名通配符""路径前缀""签名者""哈希"四个维度
    // 以及白名单优先都能直接作用于自启动项，不必另写一套判定逻辑。
    return Matcher::IsInBlacklist(config, candidate);
}

bool ReadTextFileWide(const std::wstring& path, std::wstring& content) {
    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    const std::string bytes = buffer.str();
    if (bytes.empty()) {
        content.clear();
        return true;
    }

    const size_t size = bytes.size();
    const auto* raw = reinterpret_cast<const unsigned char*>(bytes.data());

    if (size >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        // UTF-16LE（计划任务的 XML 就是这种）
        content.assign(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (size - 2) / sizeof(wchar_t));
        return true;
    }

    size_t offset = 0;
    if (size >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) {
        offset = 3;  // UTF-8 BOM
    }

    const char* data = bytes.data() + offset;
    const int dataSize = static_cast<int>(size - offset);

    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, dataSize, nullptr, 0);
    UINT codePage = CP_UTF8;
    if (length <= 0) {
        // 解不出 UTF-8 就当作本地编码（记事本另存为 ANSI 的常见情况）
        codePage = CP_ACP;
        length = MultiByteToWideChar(codePage, 0, data, dataSize, nullptr, 0);
        if (length <= 0) {
            return false;
        }
    }

    content.resize(static_cast<size_t>(length));
    MultiByteToWideChar(codePage, codePage == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0, data, dataSize,
                        content.data(), length);
    return true;
}

bool DeleteFileForce(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }

    // 先清属性：只读/隐藏/系统属性都会让 DeleteFileW 直接失败
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);

    if (DeleteFileW(path.c_str())) {
        return true;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
        return true;  // 已经不在了，视为成功
    }

    GD_LOG_WARN(L"删除文件失败：%s（错误 %lu）", path.c_str(), error);
    return false;
}

void ReportAutoStartHit(const wchar_t* category, const std::wstring& item,
                        const std::wstring& detail, bool clean) {
    if (clean) {
        GD_LOG_WARN(L"命中自启动项[%s]：%s → %s", category, item.c_str(), detail.c_str());
        Logger::Instance().LogBackup(category, item.c_str(), detail);
        return;
    }
    GD_LOG_DEBUG(L"命中自启动项[%s]（扫描模式）：%s → %s", category, item.c_str(), detail.c_str());
}

} // namespace GuardDog