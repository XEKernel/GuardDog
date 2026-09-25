// GuardDog 托盘 UI（阶段三）。
//
// 设计取向：这是一个"看得见"的通道，不是第二个控制台。
//   - 只提供查询类动作（状态、日志、只读扫描）与"临时放行"这一个干预类动作；
//   - 刻意不提供"删除/终止"类命令：UI 以普通用户身份运行，
//     把危险动作经管道暴露出去等于给本机任何进程开了一个提权后门；
//   - 退出只结束 UI 进程，不会影响防护服务本身。
//
// 编译为 GUI 子系统，入口 wWinMain，无控制台窗口。

#include <windows.h>
#include <shellapi.h>

#include <string>

#include "Core/Constants.h"
#include "Core/IPC.h"

#pragma comment(lib, "shell32.lib")

namespace {

constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr wchar_t kWindowClassName[] = L"GuardDogTrayWindow";
constexpr wchar_t kRunKeyPath[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"GuardDogUI";

HINSTANCE g_instance = nullptr;
HWND g_window = nullptr;
NOTIFYICONDATAW g_trayData{};

// 取自身 exe 路径。
// 这里自己实现而不复用 ServiceInstaller 的同名函数：UI 以普通用户运行，
// 不应该为了一个取路径的动作去链接整套服务安装逻辑。
std::wstring GetSelfPath() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length =
            GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return std::wstring();
        }
        if (length < path.size() - 1) {
            path.resize(length);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

enum MenuId : UINT {
    kMenuStatus = 1,
    kMenuLog,
    kMenuConfig,
    kMenuScan,
    kMenuAllowLast,
    kMenuWatchdog,
    kMenuAbout,
    kMenuExit,
};

void ShowInfo(const std::wstring& text, UINT flags = MB_OK | MB_ICONINFORMATION) {
    MessageBoxW(nullptr, text.c_str(), L"GuardDog", flags | MB_SETFOREGROUND);
}

// 与服务通信；失败时给出明确原因，而不是静默无响应
bool SendCommand(const std::wstring& request, std::wstring& response) {
    if (!GuardDog::IpcClient::Send(request, response)) {
        ShowInfo(L"无法连接到 GuardDog 服务。\n\n"
                 L"可能的原因：\n"
                 L"  - 主服务未安装或未启动（sc start GuardDogService）\n"
                 L"  - 服务正在重启中，稍后重试",
                 MB_OK | MB_ICONWARNING);
        return false;
    }
    return true;
}

UINT FlagsForResponse(const std::wstring& response) {
    const bool isError = response.rfind(L"ERR|", 0) == 0;
    return MB_OK | (isError ? MB_ICONWARNING : MB_ICONINFORMATION);
}

// 把 "OK|" / "ERR|" 之后的内容取出来展示
std::wstring StripStatusPrefix(const std::wstring& response) {
    const size_t separator = response.find(L'|');
    return separator == std::wstring::npos ? response : response.substr(separator + 1);
}

void ShowStatus() {
    std::wstring response;
    if (!SendCommand(L"STATUS", response)) {
        return;
    }
    ShowInfo(StripStatusPrefix(response), FlagsForResponse(response));
}

void ShowLog() {
    std::wstring response;
    if (!SendCommand(L"LOG|200", response)) {
        return;
    }
    if (response.rfind(L"ERR|", 0) == 0) {
        ShowInfo(StripStatusPrefix(response), MB_OK | MB_ICONWARNING);
        return;
    }

    // 写到临时文件再用记事本打开：比自绘只读窗口更实用（可搜索、可复制）
    wchar_t tempPath[MAX_PATH] = {};
    GetTempPathW(_countof(tempPath), tempPath);
    const std::wstring logFile = std::wstring(tempPath) + L"GuardDog_日志快照.txt";

    const std::wstring content = L"GuardDog 日志快照（由托盘 UI 拉取）\r\n\r\n" +
                                 StripStatusPrefix(response);
    HANDLE file = CreateFileW(logFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        ShowInfo(L"无法写入日志快照文件。", MB_OK | MB_ICONWARNING);
        return;
    }

    // 以 UTF-16LE + BOM 写出，记事本才能正确显示中文
    const unsigned char bom[2] = {0xFF, 0xFE};
    DWORD written = 0;
    WriteFile(file, bom, sizeof(bom), &written, nullptr);
    WriteFile(file, content.c_str(), static_cast<DWORD>(content.size() * sizeof(wchar_t)), &written,
              nullptr);
    CloseHandle(file);

    ShellExecuteW(nullptr, L"open", L"notepad.exe", logFile.c_str(), nullptr, SW_SHOWNORMAL);
}

void OpenConfig() {
    const std::wstring configPath =
        std::wstring(GuardDog::Constants::kProgramDataDir) + L"\\" +
        GuardDog::Constants::kConfigFileName;

    if (GetFileAttributesW(configPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ShowInfo(L"配置文件尚不存在：\n" + configPath +
                     L"\n\n请先启动一次 GuardDog 服务，它会自动生成默认配置。",
                 MB_OK | MB_ICONWARNING);
        return;
    }

    ShellExecuteW(nullptr, L"open", L"notepad.exe", configPath.c_str(), nullptr, SW_SHOWNORMAL);
}

void RunScan() {
    SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    std::wstring response;
    if (SendCommand(L"SCAN", response)) {
        ShowInfo(L"存量扫描结果（仅发现，不会自动处置）：\n\n" + StripStatusPrefix(response),
                 FlagsForResponse(response));
    }
    SetCursor(LoadCursorW(nullptr, IDC_ARROW));
}

void AllowLastTarget() {
    std::wstring response;
    if (SendCommand(L"ALLOW_LAST", response)) {
        ShowInfo(StripStatusPrefix(response), FlagsForResponse(response));
    }
}

void ShowWatchdogStatus() {
    // 看门狗是独立服务，直接查服务状态即可，不必绕道主服务
    std::wstring text;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        ShowInfo(L"无法打开服务控制管理器（需要管理员权限才能查询服务）。",
                 MB_OK | MB_ICONWARNING);
        return;
    }

    SC_HANDLE service = OpenServiceW(scm, GuardDog::Constants::kWatchdogServiceName,
                                     SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        text = L"看门狗服务未安装。\n\n安装命令（管理员）：\n    GuardDogWatchdog.exe install";
    } else {
        SERVICE_STATUS status{};
        if (QueryServiceStatus(service, &status)) {
            const wchar_t* stateText = L"未知";
            switch (status.dwCurrentState) {
                case SERVICE_RUNNING:       stateText = L"运行中"; break;
                case SERVICE_STOPPED:       stateText = L"已停止"; break;
                case SERVICE_START_PENDING: stateText = L"正在启动"; break;
                case SERVICE_STOP_PENDING:  stateText = L"正在停止"; break;
                default: break;
            }
            text = std::wstring(L"看门狗服务状态：") + stateText +
                   L"\n\n它每 30 秒检查一次主服务，发现未运行会自动拉起。";
        } else {
            text = L"查询看门狗状态失败。";
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);

    ShowInfo(text);
}

void ShowAbout() {
    ShowInfo(std::wstring(L"GuardDog ") + GuardDog::Constants::kVersion + L"\n" +
                 GuardDog::Constants::kBuildStage +
                 L"\n\n纯用户态防流氓软件防护工具。\n"
                 L"服务端负责监控与清理，本托盘程序仅用于查看状态。\n\n"
                 L"退出本程序不会停止防护服务。");
}

void ShowTrayMenu() {
    POINT cursor{};
    GetCursorPos(&cursor);

    HMENU menu = CreatePopupMenu();
    if (menu == nullptr) {
        return;
    }

    AppendMenuW(menu, MF_STRING, kMenuStatus, L"查看状态");
    AppendMenuW(menu, MF_STRING, kMenuLog, L"查看日志");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kMenuScan, L"手动扫描（只读）");
    AppendMenuW(menu, MF_STRING, kMenuAllowLast, L"临时放行最近处置的目标");
    AppendMenuW(menu, MF_STRING, kMenuWatchdog, L"看门狗状态");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kMenuConfig, L"打开配置文件");
    AppendMenuW(menu, MF_STRING, kMenuAbout, L"关于");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kMenuExit, L"退出（不影响防护）");

    // TrackPopupMenu 要求先让本窗口成为前台窗口，否则点击菜单外部不会消失
    SetForegroundWindow(g_window);

    const UINT command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0,
                                        g_window, nullptr);
    DestroyMenu(menu);

    switch (command) {
        case kMenuStatus:    ShowStatus(); break;
        case kMenuLog:       ShowLog(); break;
        case kMenuScan:      RunScan(); break;
        case kMenuAllowLast: AllowLastTarget(); break;
        case kMenuWatchdog:  ShowWatchdogStatus(); break;
        case kMenuConfig:    OpenConfig(); break;
        case kMenuAbout:     ShowAbout(); break;
        case kMenuExit:      DestroyWindow(g_window); break;
        default: break;
    }
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case kTrayCallbackMessage:
            if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU) {
                ShowTrayMenu();
            } else if (LOWORD(lParam) == WM_LBUTTONDBLCLK) {
                ShowStatus();
            }
            return 0;

        case WM_COMMAND:
            // 菜单未使用 TPM_RETURNCMD 时才会走到这里；保留以兼容键盘操作
            return 0;

        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_trayData);
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(window, message, wParam, lParam);
    }
}

bool InstallAutoStart() {
    const std::wstring executable = GetSelfPath();
    if (executable.empty()) {
        return false;
    }

    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKeyPath, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key,
                        nullptr) != ERROR_SUCCESS) {
        return false;
    }

    const std::wstring command = L"\"" + executable + L"\"";
    const LSTATUS status =
        RegSetValueExW(key, kRunValueName, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(command.c_str()),
                       static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

bool UninstallAutoStart() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKeyPath, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return true;  // 键不存在等于"已无自启动项"
    }
    const LSTATUS status = RegDeleteValueW(key, kRunValueName);
    RegCloseKey(key);
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

void RegisterTrayIcon() {
    g_trayData.cbSize = sizeof(g_trayData);
    g_trayData.hWnd = g_window;
    g_trayData.uID = kTrayIconId;
    g_trayData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_trayData.uCallbackMessage = kTrayCallbackMessage;
    g_trayData.hIcon = LoadIconW(nullptr, IDI_APPLICATION);  // 用系统图标，避免引入资源文件
    wcscpy_s(g_trayData.szTip, L"GuardDog 防护中（双击查看状态）");

    Shell_NotifyIconW(NIM_ADD, &g_trayData);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE /*prevInstance*/, LPWSTR commandLine,
                    int /*showCommand*/) {
    g_instance = instance;

    // 命令行：install / uninstall 用于把 UI 注册到当前用户的登录启动项
    const std::wstring command(commandLine != nullptr ? commandLine : L"");
    if (!command.empty()) {
        if (_wcsicmp(command.c_str(), L"install") == 0) {
            const bool ok = InstallAutoStart();
            MessageBoxW(nullptr,
                        ok ? L"已把 GuardDog 托盘程序加入当前用户的登录启动项。"
                           : L"写入登录启动项失败（请检查当前用户权限）。",
                        L"GuardDog", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
            return ok ? 0 : 1;
        }
        if (_wcsicmp(command.c_str(), L"uninstall") == 0) {
            const bool ok = UninstallAutoStart();
            MessageBoxW(nullptr, ok ? L"已移除登录启动项。" : L"移除登录启动项失败。", L"GuardDog",
                        MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
            return ok ? 0 : 1;
        }
    }

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.lpszClassName = kWindowClassName;

    if (RegisterClassExW(&windowClass) == 0) {
        return 1;
    }

    // 只创建消息窗口，不显示任何界面；托盘图标才是这个程序的"界面"
    g_window = CreateWindowExW(0, kWindowClassName, L"GuardDog", 0, 0, 0, 0, 0, nullptr, nullptr,
                               instance, nullptr);
    if (g_window == nullptr) {
        return 1;
    }

    RegisterTrayIcon();

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return 0;
}