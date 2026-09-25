#include "Cleaner/SoftwareRemover.h"

#include "AutoStart/AutoStartTypes.h"
#include "Cleaner/FileDestroyer.h"
#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"

#include <vector>

namespace GuardDog {

namespace {

constexpr int kMaxTreeDepth = 6;

// 需要处置的"可执行载体"。数据文件（ini/log/dat/db）不在其中：
// 它们无法被执行，删掉也不会让软件失去运行能力，反而增加误删用户数据的风险。
constexpr const wchar_t* kExecutableExtensions[] = {
    L".exe", L".dll", L".sys", L".ocx", L".cpl", L".scr", L".drv",
};

bool IsExecutableCarrier(const std::wstring& fileName) {
    const size_t dot = fileName.find_last_of(L'.');
    if (dot == std::wstring::npos) {
        return false;
    }
    const std::wstring extension = fileName.substr(dot);
    for (const wchar_t* candidate : kExecutableExtensions) {
        if (_wcsicmp(extension.c_str(), candidate) == 0) {
            return true;
        }
    }
    return false;
}

bool IsDirectoryEmpty(const std::wstring& directory) {
    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool empty = true;
    do {
        if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
            empty = false;
            break;
        }
    } while (FindNextFileW(find, &findData));

    FindClose(find);
    return empty;
}

// 递归处置一棵目录树。
// 先处理本层文件、再递归子目录，最后尝试删除已经变空的目录——
// 由深到浅地删空目录，父目录会在子目录消失后自然变为可删。
void DisposeDirectoryTree(const Config& config, const std::wstring& directory,
                          DisposeScope scope, int depth, SoftwareDisposalResult& result) {
    if (depth > kMaxTreeDepth) {
        GD_LOG_WARN(L"[软件处置] 目录层级过深，停止递归：%s", directory.c_str());
        return;
    }

    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    std::vector<std::wstring> subDirectories;
    std::vector<std::wstring> files;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        const std::wstring fullPath = directory + L"\\" + findData.cFileName;
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            subDirectories.push_back(fullPath);
        } else {
            files.push_back(fullPath);
        }
    } while (FindNextFileW(find, &findData));

    FindClose(find);

    for (const std::wstring& filePath : files) {
        if (!IsExecutableCarrier(Matcher::FileNameOf(filePath))) {
            continue;
        }

        ++result.filesScanned;
        const DestroyResult disposeResult = FileDestroyer::DestroyFile(config, filePath, scope);

        if (disposeResult.outcome == DestroyOutcome::Rejected) {
            ++result.filesSkipped;
            continue;
        }

        if (disposeResult.IsHandled()) {
            ++result.filesDisposed;
            GD_LOG_WARN(L"[软件处置] %s", disposeResult.Describe().c_str());
        } else {
            ++result.filesFailed;
            GD_LOG_ERROR(L"[软件处置] 处置失败：%s", disposeResult.Describe().c_str());
        }
    }

    for (const std::wstring& subDirectory : subDirectories) {
        DisposeDirectoryTree(config, subDirectory, scope, depth + 1, result);
    }

    if (IsDirectoryEmpty(directory)) {
        if (RemoveDirectoryW(directory.c_str())) {
            ++result.directoriesRemoved;
            GD_LOG_INFO(L"[软件处置] 已删除空目录：%s", directory.c_str());
        }
    }
}

} // namespace

std::wstring SoftwareDisposalResult::Describe() const {
    wchar_t buffer[256] = {};
    swprintf_s(buffer, L"检查 %d 个可执行文件，已处置 %d 个，失败 %d 个，跳过 %d 个，删除空目录 %d 个",
               filesScanned, filesDisposed, filesFailed, filesSkipped, directoriesRemoved);
    return std::wstring(buffer);
}

SoftwareDisposalResult SoftwareRemover::RemoveSoftware(const Config& config,
                                                       const std::wstring& imagePath) {
    const std::wstring directory = ParentDirectoryOf(imagePath);
    if (directory.empty()) {
        GD_LOG_WARN(L"[软件处置] 无法确定软件目录，跳过：%s", imagePath.c_str());
        return SoftwareDisposalResult{};
    }
    return DisposeDirectory(config, directory);
}

SoftwareDisposalResult SoftwareRemover::DisposeDirectory(const Config& config,
                                                         const std::wstring& directory) {
    SoftwareDisposalResult result;

    if (directory.empty()) {
        return result;
    }

    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        GD_LOG_WARN(L"[软件处置] 目录不存在或不是目录，跳过：%s", directory.c_str());
        return result;
    }

    // 安全闸门：目录处置不允许落在系统关键目录上。
    // 即便规则写错，也不至于把 Windows 目录当成"软件目录"来清。
    const std::wstring lowered = [&directory]() {
        std::wstring text = directory;
        for (wchar_t& ch : text) {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        return text;
    }();

    wchar_t windowsDirectory[MAX_PATH] = {};
    GetWindowsDirectoryW(windowsDirectory, _countof(windowsDirectory));
    std::wstring loweredWindows(windowsDirectory);
    for (wchar_t& ch : loweredWindows) {
        ch = static_cast<wchar_t>(towlower(ch));
    }

    if (!loweredWindows.empty() &&
        (lowered == loweredWindows || lowered.rfind(loweredWindows + L"\\", 0) == 0)) {
        GD_LOG_ERROR(L"[软件处置] 拒绝处置 Windows 系统目录：%s", directory.c_str());
        return result;
    }

    const DisposeScope scope = config.settings.removeWholeDirectory
                                   ? DisposeScope::SoftwareTree
                                   : DisposeScope::BlacklistMatch;

    GD_LOG_WARN(L"===== 开始软件整体处置：%s（范围：%s）=====", directory.c_str(),
                scope == DisposeScope::SoftwareTree ? L"整个目录树" : L"仅命中黑名单的文件");

    DisposeDirectoryTree(config, directory, scope, 0, result);

    GD_LOG_WARN(L"软件处置完成：%s", result.Describe().c_str());
    return result;
}

} // namespace GuardDog