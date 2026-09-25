#include "Core/Logger.h"

#include "Core/Constants.h"

#include <cwchar>
#include <vector>

namespace GuardDog {

namespace {

// 递归创建目录。服务首次运行时 ProgramData\GuardDog\logs 都不存在，
// CreateFile 不会自动建目录，所以必须自己逐级创建。
// 返回 ERROR_SUCCESS 或具体 Win32 错误码（用错误码而不是 bool，
// 是为了让服务启动失败时能向 SCM 上报真实原因）。
DWORD EnsureDirectoryExists(const std::wstring& path) {
    if (path.empty()) {
        return ERROR_BAD_PATHNAME;
    }

    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? ERROR_SUCCESS : ERROR_DIRECTORY;
    }

    // "C:\" 这类根目录本身已存在，不能也不需要再往上递归
    if (path.size() <= 3 && path.size() >= 2 && path[1] == L':') {
        return ERROR_SUCCESS;
    }

    const size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos > 0) {
        const DWORD parentResult = EnsureDirectoryExists(path.substr(0, pos));
        if (parentResult != ERROR_SUCCESS) {
            return parentResult;
        }
    }

    if (CreateDirectoryW(path.c_str(), nullptr)) {
        return ERROR_SUCCESS;
    }
    const DWORD error = GetLastError();
    return error == ERROR_ALREADY_EXISTS ? ERROR_SUCCESS : error;
}

int MakeDayStamp(const SYSTEMTIME& st) {
    return static_cast<int>(st.wYear) * 10000 + static_cast<int>(st.wMonth) * 100 +
           static_cast<int>(st.wDay);
}

std::wstring FormatDirectory(const std::wstring& dir) {
    std::wstring result = dir;
    while (!result.empty() && (result.back() == L'\\' || result.back() == L'/')) {
        result.pop_back();
    }
    return result;
}

} // namespace

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

LogLevel Logger::ParseLevel(const std::wstring& text) noexcept {
    std::wstring lower;
    lower.reserve(text.size());
    for (wchar_t ch : text) {
        lower.push_back(static_cast<wchar_t>(towlower(ch)));
    }

    if (lower == L"debug") return LogLevel::Debug;
    if (lower == L"info")  return LogLevel::Info;
    if (lower == L"warn" || lower == L"warning") return LogLevel::Warn;
    if (lower == L"error") return LogLevel::Error;
    return LogLevel::Info;
}

const wchar_t* Logger::LevelTag(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Debug: return L"DEBUG";
        case LogLevel::Info:  return L"INFO";
        case LogLevel::Warn:  return L"WARN";
        case LogLevel::Error: return L"ERROR";
        default:              return L"INFO";
    }
}

HRESULT Logger::Initialize(const std::wstring& logDir) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        return S_OK;
    }

    m_dir = logDir.empty()
                ? (std::wstring(Constants::kProgramDataDir) + L"\\" + Constants::kLogDirName)
                : FormatDirectory(logDir);

    const DWORD dirResult = EnsureDirectoryExists(m_dir);
    if (dirResult != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(dirResult);
    }

    const HRESULT openResult = EnsureOpenFileLocked();
    if (FAILED(openResult)) {
        return openResult;
    }

    m_initialized = true;
    return S_OK;
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_file != INVALID_HANDLE_VALUE) {
        // 服务退出前必须落盘：日志是唯一的事后审计来源
        FlushFileBuffers(m_file);
        CloseHandle(m_file);
        m_file = INVALID_HANDLE_VALUE;
    }
    m_initialized = false;
}

std::wstring Logger::GetCurrentLogPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentPath;
}

void Logger::Log(LogLevel level, const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(level, format, args);
    va_end(args);
}

void Logger::Debug(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Debug, format, args);
    va_end(args);
}

void Logger::Info(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Info, format, args);
    va_end(args);
}

void Logger::Warn(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Warn, format, args);
    va_end(args);
}

void Logger::Error(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    LogV(LogLevel::Error, format, args);
    va_end(args);
}

void Logger::LogBackup(const wchar_t* category, const wchar_t* item,
                       const std::wstring& originalValue) {
    Log(LogLevel::Warn, L"[BACKUP] 类别=%s 项=%s 原始值=[%s]", category != nullptr ? category : L"?",
        item != nullptr ? item : L"?", originalValue.c_str());
}

void Logger::LogV(LogLevel level, const wchar_t* format, va_list args) {
    if (static_cast<int>(level) < static_cast<int>(m_level)) {
        return;
    }

    // 先探测格式化后的长度：日志消息里可能带很长的路径/命令行，
    // 固定缓冲区截断会丢掉关键证据，因此按需分配。
    std::wstring message;
    va_list probe;
    va_copy(probe, args);
    const int needed = _vscwprintf(format, probe);
    va_end(probe);

    if (needed < 0) {
        message = L"<日志格式化失败>";
    } else {
        std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1, L'\0');
        _vsnwprintf_s(buffer.data(), buffer.size(), _TRUNCATE, format, args);
        message.assign(buffer.data());
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    WriteLineLocked(level, message);
}

void Logger::WriteLineLocked(LogLevel level, const std::wstring& message) {
    if (FAILED(EnsureOpenFileLocked())) {
        return;
    }

    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t prefix[128] = {};
    swprintf_s(prefix, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%-5s] [T%05lu] ", st.wYear, st.wMonth,
               st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, LevelTag(level),
               GetCurrentThreadId());

    const std::wstring line = std::wstring(prefix) + message + L"\r\n";

    // 转 UTF-8 落盘：日志可能被其他工具（PowerShell / 编辑器）读取，
    // UTF-8 比 UTF-16 兼容性更好（配合文件头 BOM，中文不会乱码）。
    const int byteCount = WideCharToMultiByte(CP_UTF8, 0, line.c_str(),
                                              static_cast<int>(line.size()), nullptr, 0, nullptr,
                                              nullptr);
    if (byteCount <= 0) {
        return;
    }

    std::string utf8(static_cast<size_t>(byteCount), '\0');
    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), utf8.data(),
                        byteCount, nullptr, nullptr);

    DWORD written = 0;
    WriteFile(m_file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

HRESULT Logger::EnsureOpenFileLocked() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    const int today = MakeDayStamp(st);

    if (m_file != INVALID_HANDLE_VALUE && today == m_currentDayStamp) {
        return S_OK;
    }

    // 跨天（或首次打开）：先把昨天的活动日志归档
    if (m_file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_file);
        CloseHandle(m_file);
        m_file = INVALID_HANDLE_VALUE;

        const std::wstring archive =
            m_dir + L"\\guarddog-" + std::to_wstring(m_currentDayStamp) + L".log";
        MoveFileExW(m_currentPath.c_str(), archive.c_str(), MOVEFILE_REPLACE_EXISTING);
    }

    const DWORD dirResult = EnsureDirectoryExists(m_dir);
    if (dirResult != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(dirResult);
    }

    m_currentPath = m_dir + L"\\" + Constants::kLogFileName;

    // 共享模式必须放开读写删除三种权限：
    //  - 服务进程与安装器/看门狗/UI 会并发写同一份日志，各自都要能以追加方式打开；
    //  - 跨天归档时需要在自身持有句柄的情况下重命名文件（依赖 FILE_SHARE_DELETE）。
    // 追加写由 FILE_APPEND_DATA 保证原子落盘，多进程交错写入也不会互相覆盖内容。
    m_file = CreateFileW(m_currentPath.c_str(), FILE_APPEND_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_file == INVALID_HANDLE_VALUE) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    m_currentDayStamp = today;

    LARGE_INTEGER size{};
    if (GetFileSizeEx(m_file, &size) && size.QuadPart == 0) {
        const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
        DWORD written = 0;
        WriteFile(m_file, bom, sizeof(bom), &written, nullptr);
    }

    PurgeOldLogsLocked();
    return S_OK;
}

void Logger::PurgeOldLogsLocked() {
    WIN32_FIND_DATAW findData{};
    const std::wstring pattern = m_dir + L"\\guarddog-*.log";
    HANDLE find = FindFirstFileW(pattern.c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER nowValue{};
    nowValue.LowPart = now.dwLowDateTime;
    nowValue.HighPart = now.dwHighDateTime;

    // FILETIME 以 100ns 为单位
    const ULONGLONG keepSpan =
        static_cast<ULONGLONG>(Constants::kLogKeepDays) * 24ULL * 60ULL * 60ULL * 10000000ULL;

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            continue;
        }
        if (wcscmp(findData.cFileName, Constants::kLogFileName) == 0) {
            continue;
        }

        ULARGE_INTEGER fileTime{};
        fileTime.LowPart = findData.ftLastWriteTime.dwLowDateTime;
        fileTime.HighPart = findData.ftLastWriteTime.dwHighDateTime;

        if (nowValue.QuadPart > fileTime.QuadPart &&
            (nowValue.QuadPart - fileTime.QuadPart) > keepSpan) {
            const std::wstring fullPath = m_dir + L"\\" + findData.cFileName;
            DeleteFileW(fullPath.c_str());
        }
    } while (FindNextFileW(find, &findData));

    FindClose(find);
}

} // namespace GuardDog