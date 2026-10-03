#include "Cleaner/FileDestroyer.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"
#include "Core/ScopeHandle.h"
#include "Monitor/ProcessKiller.h"

#include <restartmanager.h>

#include <vector>

#pragma comment(lib, "RstrtMgr.lib")

namespace GuardDog {

namespace {

// PE 头只有几百字节有实际意义（MZ 头 + DOS stub + PE 签名 + 可选头），
// 覆写前 1KB 足以让加载器彻底无法识别。
constexpr DWORD kPeHeaderSize = 1024;

constexpr DWORD kTerminateWaitMs = 5000;

struct RmSessionGuard {
    DWORD handle = 0;
    ~RmSessionGuard() {
        if (handle != 0) {
            RmEndSession(handle);
        }
    }
};

// 直接删除：先清属性再删。
// 流氓软件常给自身文件加只读/隐藏/系统属性，让最朴素的 DeleteFileW 直接失败。
bool TryDeleteDirect(const std::wstring& path) {
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(path.c_str()) != FALSE;
}

bool TryMoveToReboot(const std::wstring& path) {
    // 需要写 PendingFileRenameOperations 的权限，服务以 LocalSystem 运行天然满足
    return MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE;
}

// 覆写 PE 头（方法一：直接写入文件）
bool OverwriteViaWrite(const std::wstring& path) {
    ScopeHandle file;
    file.Reset(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.IsValid()) {
        return false;
    }

    BYTE zeros[kPeHeaderSize] = {};
    DWORD written = 0;
    if (!WriteFile(file.Get(), zeros, sizeof(zeros), &written, nullptr) ||
        written != sizeof(zeros)) {
        return false;
    }

    FlushFileBuffers(file.Get());
    return true;
}

// 覆写 PE 头（方法二：内存映射）。
// 某些情况下文件被以允许共享读取的方式打开，直接 WriteFile 会被拒，
// 但共享映射写入仍可能成功——多一条路径就多一分成功率。
bool OverwriteViaMapping(const std::wstring& path) {
    ScopeHandle file;
    file.Reset(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.IsValid()) {
        return false;
    }

    ScopeHandle mapping;
    mapping.Reset(CreateFileMappingW(file.Get(), nullptr, PAGE_READWRITE, 0, kPeHeaderSize, nullptr));
    if (!mapping.IsValid()) {
        return false;
    }

    void* view = MapViewOfFile(mapping.Get(), FILE_MAP_WRITE, 0, 0, kPeHeaderSize);
    if (view == nullptr) {
        return false;
    }

    SecureZeroMemory(view, kPeHeaderSize);
    FlushViewOfFile(view, kPeHeaderSize);
    UnmapViewOfFile(view);
    return true;
}

} // namespace

std::wstring DestroyResult::Describe() const {
    const wchar_t* outcomeText = L"未知";
    switch (outcome) {
        case DestroyOutcome::AlreadyGone:        outcomeText = L"文件已不存在"; break;
        case DestroyOutcome::Deleted:            outcomeText = L"已删除"; break;
        case DestroyOutcome::PeHeaderDestroyed:  outcomeText = L"删除失败，PE 头已破坏（程序永久报废）"; break;
        case DestroyOutcome::ScheduledForReboot: outcomeText = L"已登记重启后删除"; break;
        case DestroyOutcome::Rejected:           outcomeText = L"未命中黑名单，已拒绝处置"; break;
        case DestroyOutcome::Failed:             outcomeText = L"处置失败"; break;
    }

    std::wstring text = L"[" + std::wstring(outcomeText) + L"] " + path;
    if (!detail.empty()) {
        text += L"（" + detail + L"）";
    }
    return text;
}

bool FileDestroyer::IsPortableExecutable(const std::wstring& path) {
    ScopeHandle file;
    file.Reset(CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.IsValid()) {
        return false;
    }

    IMAGE_DOS_HEADER dosHeader{};
    DWORD read = 0;
    if (!ReadFile(file.Get(), &dosHeader, sizeof(dosHeader), &read, nullptr) ||
        read != sizeof(dosHeader)) {
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    // 定位 PE 签名（e_lfanew 指向 "PE\0\0"）
    LARGE_INTEGER offset{};
    offset.QuadPart = dosHeader.e_lfanew;
    if (!SetFilePointerEx(file.Get(), offset, nullptr, FILE_BEGIN)) {
        return false;
    }

    DWORD signature = 0;
    if (!ReadFile(file.Get(), &signature, sizeof(signature), &read, nullptr) ||
        read != sizeof(signature)) {
        return false;
    }
    return signature == IMAGE_NT_SIGNATURE;
}

std::vector<DWORD> FileDestroyer::FindProcessesLockingFile(const std::wstring& path) {
    std::vector<DWORD> processIds;

    RmSessionGuard session;
    wchar_t sessionKey[CCH_RM_SESSION_KEY + 1] = {};
    if (RmStartSession(&session.handle, 0, sessionKey) != ERROR_SUCCESS) {
        return processIds;
    }

    const wchar_t* resources[] = {path.c_str()};
    if (RmRegisterResources(session.handle, 1, resources, 0, nullptr, 0, nullptr) != ERROR_SUCCESS) {
        return processIds;
    }

    UINT needed = 0;
    UINT count = 0;
    DWORD rebootReasons = 0;

    DWORD status = RmGetList(session.handle, &needed, &count, nullptr, &rebootReasons);
    if (status == ERROR_MORE_DATA && needed > 0) {
        std::vector<RM_PROCESS_INFO> infos(needed);
        count = needed;
        status = RmGetList(session.handle, &needed, &count, infos.data(), &rebootReasons);
        if (status == ERROR_SUCCESS) {
            for (UINT i = 0; i < count; ++i) {
                const DWORD processId = infos[i].Process.dwProcessId;
                if (processId != 0) {
                    processIds.push_back(processId);
                }
            }
        }
    }

    return processIds;
}

bool FileDestroyer::OverwritePeHeader(const std::wstring& path) {
    if (!IsPortableExecutable(path)) {
        // 不是 PE 文件：破坏头部没有意义，也避免误动数据文件
        GD_LOG_WARN(L"目标不是 PE 文件，跳过头部覆写：%s", path.c_str());
        return false;
    }

    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);

    if (OverwriteViaWrite(path)) {
        GD_LOG_WARN(L"已覆写 PE 头：%s（前 %lu 字节清零）", path.c_str(), kPeHeaderSize);
        return true;
    }

    if (OverwriteViaMapping(path)) {
        GD_LOG_WARN(L"已通过内存映射覆写 PE 头：%s", path.c_str());
        return true;
    }

    GD_LOG_ERROR(L"覆写 PE 头失败：%s（错误 %lu）", path.c_str(), GetLastError());
    return false;
}

bool FileDestroyer::IsTreeDisposalAllowed(const std::wstring& pathOrDirectory) {
    std::wstring directory = pathOrDirectory;

    // 传入文件路径时按它所在目录判断（调用方通常给的是目标文件）
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        const size_t separator = directory.find_last_of(L"\\/");
        directory = (separator == std::wstring::npos) ? std::wstring() : directory.substr(0, separator);
    }

    // 统一成不带尾部分隔符的形式，便于比较
    while (!directory.empty() && (directory.back() == L'\\' || directory.back() == L'/')) {
        directory.pop_back();
    }

    // 盘根（"C:"）或空路径：直接拒绝
    if (directory.size() <= 2) {
        GD_LOG_ERROR(L"拒绝整树处置盘根目录：%s", pathOrDirectory.c_str());
        return false;
    }

    // 保护位置分两类，判定方式不同——这是关键区别：
    //   系统目录：本身与其下所有子目录都拒绝（整树清理系统目录没有正当场景）
    //   公共场所：只拒绝目录本身。它们下面按软件名分的子目录（Program Files\某软件）
    //             正是正常的清理目标，连子目录一起拒绝等于让功能失效
    static const wchar_t* const kSystemRoots[] = {
        L"C:\\Windows",
        L"C:\\Program Files\\Common Files",
        L"C:\\Program Files (x86)\\Common Files",
        L"C:\\Program Files\\WindowsApps",
    };
    static const wchar_t* const kSharedRoots[] = {
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        L"C:\\ProgramData",
        L"C:\\Users",
    };

    for (const wchar_t* systemRoot : kSystemRoots) {
        const size_t length = wcslen(systemRoot);
        // 含边界检查的前缀比较：C:\Windows.old 不该被 C:\Windows 误伤
        if (_wcsnicmp(directory.c_str(), systemRoot, length) == 0 &&
            (directory.size() == length || directory[length] == L'\\')) {
            GD_LOG_ERROR(L"拒绝整树处置系统目录：%s", directory.c_str());
            return false;
        }
    }

    for (const wchar_t* sharedRoot : kSharedRoots) {
        // 完全相等才拒绝（忽略大小写）：只拦"目录本身"，放行其下的软件子目录
        if (directory.size() == wcslen(sharedRoot) &&
            _wcsnicmp(directory.c_str(), sharedRoot, directory.size()) == 0) {
            GD_LOG_ERROR(L"拒绝整树处置公共目录本身：%s", directory.c_str());
            return false;
        }
    }

    return true;
}

DestroyResult FileDestroyer::DestroyFile(const Config& config, const std::wstring& path,
                                         DisposeScope scope) {
    DestroyResult result;
    result.path = path;

    if (path.empty()) {
        result.outcome = DestroyOutcome::Failed;
        result.detail = L"路径为空";
        return result;
    }

    // 纵深防御：即便调用方已经校验过，这里再校验一次。
    // 文件处置是不可逆操作，"多校验一次"的成本远低于误删用户文件。
    bool authorized = Matcher::IsInBlacklist(config, path);

    // 目录树授权仍然要求配置显式开启：避免调用方只是误传了一个 scope 参数
    // 就把整个目录的文件都清掉。
    if (!authorized && scope == DisposeScope::SoftwareTree) {
        authorized = config.settings.removeWholeDirectory;
    }

    if (!authorized) {
        GD_LOG_ERROR(L"拒绝处置未授权文件：%s", path.c_str());
        result.outcome = DestroyOutcome::Rejected;
        return result;
    }

    // 纵深防御：即使已获得目录树授权，危险位置也一律拒绝。
    // 授权来自调用方，而调用方传入的目录往往是从进程路径推导出来的——
    // 如果目标恰好在盘根下，整树处置就会从整个盘铺开。
    if (scope == DisposeScope::SoftwareTree && !IsTreeDisposalAllowed(path)) {
        GD_LOG_ERROR(L"拒绝整树处置危险位置：%s", path.c_str());
        result.outcome = DestroyOutcome::Rejected;
        return result;
    }

    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        result.outcome = DestroyOutcome::AlreadyGone;
        return result;
    }

    Logger::Instance().LogBackup(L"文件处置", path.c_str(),
                                 L"(即将删除，原文件属性与内容不再单独备份)");

    // ---- F1 直接删除 ----
    if (TryDeleteDirect(path)) {
        GD_LOG_WARN(L"[文件处置] 已直接删除：%s", path.c_str());
        result.outcome = DestroyOutcome::Deleted;
        return result;
    }
    const DWORD directError = GetLastError();

    // ---- F2 解除占用后删除 ----
    // 用 Restart Manager 找出占用者，先挂起再终止，然后重试删除。
    //
    // 安全边界：只终止"本身就是黑名单目标"的占用者。
    // 文件被占用是很常见的现象——杀毒软件扫描、explorer 预览、索引服务都可能短时持有句柄。
    // 无差别终止占用者会把系统拖垮（杀掉 explorer 等于桌面重启），
    // 这类情况宁可走 F3：毁掉 PE 头 + 登记重启删除，同样能让目标永久报废。
    const std::vector<DWORD> lockers = FindProcessesLockingFile(path);
    if (!lockers.empty()) {
        std::vector<DWORD> terminable;
        for (const DWORD processId : lockers) {
            const std::wstring ownerPath = ProcessKiller::QueryImagePath(processId);
            if (ownerPath.empty()) {
                GD_LOG_WARN(L"[文件处置] 无法确定占用进程的映像路径，跳过终止：pid=%lu", processId);
                continue;
            }

            if (!Matcher::IsInBlacklist(config, ownerPath)) {
                GD_LOG_WARN(L"[文件处置] 占用进程未命中黑名单，跳过终止以免误伤：pid=%lu 路径=%s",
                            processId, ownerPath.c_str());
                continue;
            }

            terminable.push_back(processId);
        }

        std::wstring lockerText;
        for (const DWORD processId : terminable) {
            const std::wstring ownerPath = ProcessKiller::QueryImagePath(processId);
            if (!lockerText.empty()) {
                lockerText += L", ";
            }
            lockerText += std::to_wstring(processId);
            if (!ownerPath.empty()) {
                lockerText += L"(" + ownerPath + L")";
            }

            ProcessKiller::SuspendProcess(processId);
            if (!ProcessKiller::TerminateProcessById(processId)) {
                ProcessKiller::ForceKillWithTaskkill(processId);
            }
        }

        if (!terminable.empty()) {
            GD_LOG_WARN(L"[文件处置] 已终止占用进程：%s（%s）", path.c_str(), lockerText.c_str());

            // 等文件句柄真正释放
            for (int attempt = 0; attempt < 10; ++attempt) {
                Sleep(200);
                if (TryDeleteDirect(path)) {
                    GD_LOG_WARN(L"[文件处置] 解除占用后删除成功：%s", path.c_str());
                    result.outcome = DestroyOutcome::Deleted;
                    result.detail = L"终止占用进程后删除";
                    return result;
                }
            }
        }
    }

    // ---- F3 登记重启删除 + 覆写 PE 头（双保险）----
    result.detail = L"直接删除失败，错误 " + std::to_wstring(directError);

    bool headerDestroyed = false;
    if (config.settings.destroyPeHeader) {
        headerDestroyed = OverwritePeHeader(path);
    }

    bool rebootScheduled = false;
    if (config.settings.delayDeleteOnReboot) {
        rebootScheduled = TryMoveToReboot(path);
        if (rebootScheduled) {
            GD_LOG_WARN(L"[文件处置] 已登记重启后删除：%s", path.c_str());
        }
    }

    // 删不掉但头已废，等于达成目的：程序再也不可能被加载
    if (headerDestroyed) {
        result.outcome = DestroyOutcome::PeHeaderDestroyed;
        if (rebootScheduled) {
            result.detail += L"，并已登记重启后删除";
        }
        return result;
    }

    if (rebootScheduled) {
        result.outcome = DestroyOutcome::ScheduledForReboot;
        return result;
    }

    result.outcome = DestroyOutcome::Failed;
    return result;
}

} // namespace GuardDog