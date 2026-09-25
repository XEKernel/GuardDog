#include "AutoStart/AutoStartScanner.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/ProcessRunner.h"

#include <vector>

namespace GuardDog {
namespace Cleaners {

namespace {

constexpr int kMaxTaskTreeDepth = 6;

// 计划任务的定义文件是 XML，我们只需要其中的 <Command> 与 <Arguments>。
// 为此引入完整 XML 解析器不划算，直接按标签找文本即可——任务定义的结构很固定。
std::vector<std::wstring> ExtractTagValues(const std::wstring& xml, const std::wstring& tag) {
    std::vector<std::wstring> values;

    const std::wstring openTag = L"<" + tag + L">";
    const std::wstring closeTag = L"</" + tag + L">";

    size_t position = 0;
    for (;;) {
        const size_t start = xml.find(openTag, position);
        if (start == std::wstring::npos) {
            break;
        }
        const size_t end = xml.find(closeTag, start);
        if (end == std::wstring::npos) {
            break;
        }
        values.push_back(xml.substr(start + openTag.size(), end - start - openTag.size()));
        position = end + closeTag.size();
    }

    return values;
}

void CollectTaskFiles(const std::wstring& directory, std::vector<std::wstring>& files, int depth) {
    if (depth > kMaxTaskTreeDepth) {
        return;
    }

    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }

        const std::wstring fullPath = directory + L"\\" + findData.cFileName;
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            CollectTaskFiles(fullPath, files, depth + 1);
        } else {
            files.push_back(fullPath);
        }
    } while (FindNextFileW(find, &findData));

    FindClose(find);
}

// 由定义文件路径推导任务名：Tasks 目录下的相对路径（去掉 .job 后缀）
std::wstring TaskNameFromPath(const std::wstring& tasksRoot, const std::wstring& filePath) {
    if (filePath.size() <= tasksRoot.size() + 1) {
        return std::wstring();
    }

    std::wstring relative = filePath.substr(tasksRoot.size() + 1);
    if (relative.size() > 4 && _wcsicmp(relative.c_str() + relative.size() - 4, L".job") == 0) {
        relative.resize(relative.size() - 4);
    }
    return relative;
}

// 禁用并删除计划任务。
// 用 schtasks 而不是直接删定义文件：任务计划程序会把任务状态缓存在服务端，
// 只删文件可能出现"任务仍在运行且状态变成孤立"的情况。
bool RemoveScheduledTask(const std::wstring& taskName) {
    const std::wstring quoted = L"\"" + taskName + L"\"";

    // 先禁用再删除：即使删除失败，也已确保它不再自启动
    if (!RunHiddenCommand(L"schtasks.exe /Change /TN " + quoted + L" /DISABLE")) {
        GD_LOG_WARN(L"禁用计划任务失败：%s", taskName.c_str());
    } else {
        GD_LOG_INFO(L"计划任务已禁用：%s", taskName.c_str());
    }

    if (!RunHiddenCommand(L"schtasks.exe /Delete /TN " + quoted + L" /F")) {
        GD_LOG_ERROR(L"删除计划任务失败：%s（已保留为禁用状态）", taskName.c_str());
        return false;
    }

    GD_LOG_INFO(L"计划任务已删除：%s", taskName.c_str());
    return true;
}

} // namespace

CleanResult CleanScheduledTasks(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    CleanResult result;

    wchar_t windowsDirectory[MAX_PATH] = {};
    if (GetWindowsDirectoryW(windowsDirectory, _countof(windowsDirectory)) == 0) {
        GD_LOG_WARN(L"获取 Windows 目录失败：错误 %lu", GetLastError());
        return result;
    }

    const std::wstring tasksRoot = std::wstring(windowsDirectory) + L"\\System32\\Tasks";

    std::vector<std::wstring> taskFiles;
    CollectTaskFiles(tasksRoot, taskFiles, 0);

    for (const std::wstring& filePath : taskFiles) {
        std::wstring xml;
        if (!ReadTextFileWide(filePath, xml) || xml.empty()) {
            continue;
        }

        const std::vector<std::wstring> commands = ExtractTagValues(xml, L"Command");
        if (commands.empty()) {
            continue;  // 不是可执行型任务
        }
        const std::vector<std::wstring> arguments = ExtractTagValues(xml, L"Arguments");

        ++result.scanned;

        const std::wstring taskName = TaskNameFromPath(tasksRoot, filePath);
        if (taskName.empty()) {
            continue;
        }

        // 逐个 <Command> 判定（一个任务可能有多个动作）
        bool hit = false;
        std::wstring hitDetail;
        for (size_t i = 0; i < commands.size(); ++i) {
            std::wstring commandLine = commands[i];
            if (i < arguments.size() && !arguments[i].empty()) {
                commandLine += L" " + arguments[i];
            }
            if (IsTargetCommand(config, commandLine)) {
                hit = true;
                hitDetail = commandLine;
                break;
            }
        }

        if (!hit) {
            continue;
        }

        ++result.matched;
        ReportAutoStartHit(L"计划任务", taskName, hitDetail, clean);

        if (!clean) {
            continue;
        }

        if (RemoveScheduledTask(taskName)) {
            ++result.removed;
        } else {
            ++result.failed;
        }
    }

    return result;
}

} // namespace Cleaners
} // namespace GuardDog