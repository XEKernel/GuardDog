// 规则管理界面实现（可视化编辑黑名单规则 + 关键防护开关）。
//
// 设计取向：
//   - 以"保留原始配置树 + 只覆写目标字段"的方式回写文件，用户手工写的
//     白名单、说明字段、未知字段都不会因为用了一次界面就丢失；
//   - 保存前的校验面向"会把防护带偏的写法"：空规则名、无任何匹配条件的规则；
//   - 保存后通过 IPC 的 RELOAD 让服务立即用上新配置（服务本身 1 秒内也会检测到
//     文件变更并热重载，IPC 只是让生效时刻更确定、并给用户一个明确反馈）。
//
// 界面全部用通用控件手工布局（项目零资源文件约束，不使用 .rc 对话框模板）。

#include "UI/RuleManager.h"

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include <string>
#include <vector>

#include "Core/Constants.h"
#include "Core/IPC.h"
#include "Core/Json.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

namespace GuardDog {

namespace {

using GuardDog::JsonValue;

// ---------------------------------------------------------------------------
// 常量与控件 ID
// ---------------------------------------------------------------------------

constexpr wchar_t kManagerClassName[] = L"GuardDogRuleManager";
constexpr wchar_t kEditClassName[] = L"GuardDogRuleEdit";
constexpr int kManagerWidth = 1000;
constexpr int kManagerHeight = 640;
constexpr int kEditWidth = 680;
constexpr int kEditHeight = 600;

enum ControlId : int {
    kIdRuleList = 3000,
    kIdAddRule = 3010,
    kIdEditRule,
    kIdDeleteRule,
    kIdToggleRule,
    kIdSaveRules,
    kIdCloseManager,
    kIdBlockInstall = 3020,
    kIdCleanLegacy,
    kIdRemoveWhole,
    kIdDestroyPe,

    kIdNameEdit = 3030,
    kIdProcessEdit,
    kIdPathEdit,
    kIdSignerEdit,
    kIdHashEdit,
    kIdEnabledCheck,
    kIdEditOk = 3040,
    kIdEditCancel,
};

constexpr int kListColumnCount = 6;
const wchar_t* const kListColumnTitles[kListColumnCount] = {
    L"状态", L"规则名", L"进程名", L"路径", L"签名者", L"SHA-256",
};
constexpr int kListColumnWidths[kListColumnCount] = {60, 190, 210, 230, 130, 120};

// ---------------------------------------------------------------------------
// 数据结构
// ---------------------------------------------------------------------------

// 规则草稿：界面上编辑中的规则，保存时才转换成 JSON
struct RuleDraft {
    std::wstring name;
    bool enabled = true;
    std::vector<std::wstring> processNames;
    std::vector<std::wstring> paths;
    std::vector<std::wstring> signers;
    std::vector<std::wstring> hashes;
};

// 管理窗口状态。
// 单例静态：界面在任意时刻只允许打开一个实例（ShowRuleManagerDialog 负责保证）。
struct ManagerState {
    HWND window = nullptr;
    HWND list = nullptr;
    HWND blockInstallCheck = nullptr;
    HWND cleanLegacyCheck = nullptr;
    HWND removeWholeCheck = nullptr;
    HWND destroyPeCheck = nullptr;
    HFONT font = nullptr;
    std::vector<RuleDraft> rules;

    // 原始配置树：保存时只覆写 blacklist 与 settings 中的受管字段，
    // 其余内容（白名单、startup_mode、未知字段）原样保留
    JsonValue root;
    bool loaded = false;
    std::wstring configPath;
    std::wstring loadError;
};

ManagerState g_manager;

// 编辑对话框状态（通过 GWLP_USERDATA 挂到窗口上，避免全局变量被并发复用）
struct EditDialogState {
    HWND window = nullptr;
    HWND nameEdit = nullptr;
    HWND processEdit = nullptr;
    HWND pathEdit = nullptr;
    HWND signerEdit = nullptr;
    HWND hashEdit = nullptr;
    HWND enabledCheck = nullptr;
    HFONT font = nullptr;
    RuleDraft draft;
    bool confirmed = false;
};

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

std::wstring ConfigPath() {
    return std::wstring(Constants::kProgramDataDir) + L"\\" + Constants::kConfigFileName;
}

std::wstring Trim(const std::wstring& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && (text[begin] == L' ' || text[begin] == L'\t')) {
        ++begin;
    }
    while (end > begin && (text[end - 1] == L' ' || text[end - 1] == L'\t' || text[end - 1] == L'\r')) {
        --end;
    }
    return text.substr(begin, end - begin);
}

std::wstring GetEditText(HWND edit) {
    if (edit == nullptr) {
        return std::wstring();
    }
    const int length = GetWindowTextLengthW(edit);
    if (length <= 0) {
        return std::wstring();
    }
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    const int copied = GetWindowTextW(edit, text.data(), length + 1);
    text.resize(copied > 0 ? static_cast<size_t>(copied) : 0);
    return text;
}

void SetEditText(HWND edit, const std::wstring& text) {
    if (edit != nullptr) {
        SetWindowTextW(edit, text.c_str());
    }
}

// 多行文本 → 列表：按行拆分、去空白、去空行、去重。
// 去重是便利性处理：用户从多处复制粘贴时重复项没有任何语义价值。
std::vector<std::wstring> SplitLines(const std::wstring& text) {
    std::vector<std::wstring> result;
    size_t start = 0;
    while (start <= text.size()) {
        size_t end = text.find_first_of(L"\r\n", start);
        if (end == std::wstring::npos) {
            end = text.size();
        }
        const std::wstring line = Trim(text.substr(start, end - start));
        if (!line.empty()) {
            bool duplicated = false;
            for (const std::wstring& existing : result) {
                if (_wcsicmp(existing.c_str(), line.c_str()) == 0) {
                    duplicated = true;
                    break;
                }
            }
            if (!duplicated) {
                result.push_back(line);
            }
        }
        if (end == text.size()) {
            break;
        }
        // 跳过 \r\n 两个字符或单个 \n
        start = end + ((text[end] == L'\r' && end + 1 < text.size() && text[end + 1] == L'\n') ? 2 : 1);
    }
    return result;
}

std::wstring Join(const std::vector<std::wstring>& items, const wchar_t* separator) {
    std::wstring result;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            result += separator;
        }
        result += items[i];
    }
    return result;
}

// 列表单元格文本：太长会撑破列宽，截断展示（截断只影响显示，不影响保存的内容）
std::wstring ForCell(const std::vector<std::wstring>& items) {
    std::wstring text = Join(items, L"; ");
    constexpr size_t kMaxCellChars = 60;
    if (text.size() > kMaxCellChars) {
        text.resize(kMaxCellChars - 3);
        text += L"...";
    }
    return text;
}

std::wstring ResponseText(const std::wstring& response) {
    const size_t separator = response.find(L'|');
    return separator == std::wstring::npos ? response : response.substr(separator + 1);
}

void ShowMessage(HWND owner, const std::wstring& text, UINT flags) {
    MessageBoxW(owner, text.c_str(), L"GuardDog 规则管理", flags | MB_SETFOREGROUND);
}

// 从 JSON 读字符串数组（与 ConfigManager 的读取逻辑同源，非法项直接忽略）
std::vector<std::wstring> ReadStringArray(const JsonValue& value) {
    std::vector<std::wstring> result;
    if (!value.IsArray()) {
        return result;
    }
    for (size_t i = 0; i < value.GetSize(); ++i) {
        const JsonValue& item = value.At(i);
        if (item.IsString()) {
            std::wstring text = item.AsString();
            if (!text.empty()) {
                result.push_back(std::move(text));
            }
        }
    }
    return result;
}

JsonValue MakeStringArray(const std::vector<std::wstring>& items) {
    JsonValue array = JsonValue::MakeArray();
    for (const std::wstring& item : items) {
        array.PushBack(JsonValue::MakeString(item));
    }
    return array;
}

// ---------------------------------------------------------------------------
// 加载配置 → 界面状态
// ---------------------------------------------------------------------------

bool LoadConfigIntoState() {
    g_manager.configPath = ConfigPath();
    g_manager.rules.clear();
    g_manager.loaded = false;

    std::wstring error;
    JsonValue root = JsonValue::ParseFile(g_manager.configPath, &error);
    if (root.IsNull()) {
        g_manager.root = JsonValue::MakeObject();
        g_manager.loadError = L"无法读取配置文件：" + error + L"\n\n路径：" + g_manager.configPath +
                              L"\n\n配置文件由服务首次启动时自动生成，请先启动一次 GuardDog 服务。";
        return false;
    }
    g_manager.root = std::move(root);

    const JsonValue& blacklist = g_manager.root.Find(L"blacklist");
    if (blacklist.IsArray()) {
        for (size_t i = 0; i < blacklist.GetSize(); ++i) {
            const JsonValue& item = blacklist.At(i);
            if (!item.IsObject()) {
                continue;
            }
            RuleDraft draft;
            draft.name = item.Find(L"name").AsString(L"(未命名规则)");
            draft.enabled = item.Find(L"enabled").AsBool(true);
            draft.processNames = ReadStringArray(item.Find(L"process_names"));
            draft.paths = ReadStringArray(item.Find(L"paths"));
            draft.signers = ReadStringArray(item.Find(L"signers"));
            draft.hashes = ReadStringArray(item.Find(L"hashes"));
            g_manager.rules.push_back(std::move(draft));
        }
    }

    // 防护开关：默认值必须与服务端解析默认值一致，否则界面上显示的
    // 会和实际生效的配置不一致（例如服务默认开、界面默认关）
    if (g_manager.window != nullptr) {
        const JsonValue& settings = g_manager.root.Find(L"settings");
        const auto setCheck = [&settings](HWND checkbox, const wchar_t* key, bool fallback) {
            if (checkbox == nullptr) {
                return;
            }
            SendMessageW(checkbox, BM_SETCHECK,
                         settings.Find(key).AsBool(fallback) ? BST_CHECKED : BST_UNCHECKED, 0);
        };
        setCheck(g_manager.blockInstallCheck, L"block_install", true);
        setCheck(g_manager.cleanLegacyCheck, L"clean_legacy_on_start", false);
        setCheck(g_manager.removeWholeCheck, L"remove_whole_directory", false);
        setCheck(g_manager.destroyPeCheck, L"destroy_pe_header", true);
    }

    g_manager.loaded = true;
    g_manager.loadError.clear();
    return true;
}

// ---------------------------------------------------------------------------
// 规则列表
// ---------------------------------------------------------------------------

void RefreshRuleList() {
    if (g_manager.list == nullptr) {
        return;
    }

    SendMessageW(g_manager.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_manager.list);

    for (size_t i = 0; i < g_manager.rules.size(); ++i) {
        const RuleDraft& rule = g_manager.rules[i];

        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = static_cast<int>(i);
        item.lParam = static_cast<LPARAM>(i);
        item.pszText = const_cast<wchar_t*>(rule.enabled ? L"启用" : L"停用");
        const int row = ListView_InsertItem(g_manager.list, &item);
        if (row < 0) {
            continue;
        }

        // 列表单元格不改内容，只展示；编辑一律走"编辑"按钮，避免误触即改
        const std::wstring cells[kListColumnCount - 1] = {
            rule.name,
            ForCell(rule.processNames),
            ForCell(rule.paths),
            ForCell(rule.signers),
            ForCell(rule.hashes),
        };
        for (int column = 1; column < kListColumnCount; ++column) {
            ListView_SetItemText(g_manager.list, row, column,
                                 const_cast<wchar_t*>(cells[column - 1].c_str()));
        }
    }

    SendMessageW(g_manager.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_manager.list, nullptr, TRUE);
}

int SelectedRuleIndex() {
    if (g_manager.list == nullptr) {
        return -1;
    }
    const int row = ListView_GetNextItem(g_manager.list, -1, LVNI_SELECTED);
    if (row < 0) {
        return -1;
    }

    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = row;
    if (!ListView_GetItem(g_manager.list, &item)) {
        return -1;
    }
    return static_cast<int>(item.lParam);
}

// ---------------------------------------------------------------------------
// 规则编辑对话框
// ---------------------------------------------------------------------------

void CreateEditControls(EditDialogState* state, HWND window) {
    const HFONT font = state->font;
    const auto addLabel = [&](const wchar_t* text, int x, int y, int width, int height) {
        HWND label = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT, x, y,
                                     width, height, window, nullptr, nullptr, nullptr);
        SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return label;
    };

    addLabel(L"规则名（显示用，同时参与安装拦截的目录名匹配）", 16, 12, kEditWidth - 32, 18);
    state->nameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 16, 32,
                                      kEditWidth - 32, 26, window,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdNameEdit)),
                                      nullptr, nullptr);

    addLabel(L"进程名（每行一个，支持通配符，例如：推广*.exe）", 16, 66, kEditWidth - 32, 18);
    state->processEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
            ES_WANTRETURN,
        16, 86, kEditWidth - 32, 80, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdProcessEdit)), nullptr, nullptr);

    addLabel(L"文件路径（每行一个，支持 * 通配；安装目录可写这个）", 16, 172, kEditWidth - 32, 18);
    state->pathEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
            ES_WANTRETURN,
        16, 192, kEditWidth - 32, 80, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdPathEdit)), nullptr, nullptr);

    addLabel(L"签名者（每行一个，与文件数字签名的签署主体一致）", 16, 278, kEditWidth - 32, 18);
    state->signerEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
            ES_WANTRETURN,
        16, 298, kEditWidth - 32, 70, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdSignerEdit)), nullptr, nullptr);

    addLabel(L"SHA-256（每行一个，可带 sha256: 前缀）", 16, 374, kEditWidth - 32, 18);
    state->hashEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
            ES_WANTRETURN,
        16, 394, kEditWidth - 32, 70, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdHashEdit)), nullptr, nullptr);

    state->enabledCheck = CreateWindowExW(
        0, L"BUTTON", L"启用此规则（停用后规则保留但不生效）",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 16, 474, kEditWidth - 32, 22, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEnabledCheck)), nullptr, nullptr);

    const auto addButton = [&](const wchar_t* text, int id, int x, int y, int width, int height,
                               bool defaultButton) {
        HWND button = CreateWindowExW(
            0, L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (defaultButton ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON),
            x, y, width, height, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr,
            nullptr);
        SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    };
    addButton(L"确定", kIdEditOk, kEditWidth - 216, kEditHeight - 52, 96, 34, true);
    addButton(L"取消", kIdEditCancel, kEditWidth - 110, kEditHeight - 52, 96, 34, false);

    const HWND edits[] = {state->nameEdit,  state->processEdit, state->pathEdit,
                          state->signerEdit, state->hashEdit,   state->enabledCheck};
    for (HWND edit : edits) {
        SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
}

void PopulateEditDialog(EditDialogState* state) {
    SetEditText(state->nameEdit, state->draft.name);
    SetEditText(state->processEdit, Join(state->draft.processNames, L"\r\n"));
    SetEditText(state->pathEdit, Join(state->draft.paths, L"\r\n"));
    SetEditText(state->signerEdit, Join(state->draft.signers, L"\r\n"));
    SetEditText(state->hashEdit, Join(state->draft.hashes, L"\r\n"));
    SendMessageW(state->enabledCheck, BM_SETCHECK, state->draft.enabled ? BST_CHECKED : BST_UNCHECKED,
                 0);
}

bool ReadBackEditDialog(EditDialogState* state) {
    RuleDraft draft;
    draft.name = Trim(GetEditText(state->nameEdit));
    draft.enabled = SendMessageW(state->enabledCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    draft.processNames = SplitLines(GetEditText(state->processEdit));
    draft.paths = SplitLines(GetEditText(state->pathEdit));
    draft.signers = SplitLines(GetEditText(state->signerEdit));
    draft.hashes = SplitLines(GetEditText(state->hashEdit));

    if (draft.name.empty()) {
        ShowMessage(state->window, L"请填写规则名。\n\n规则名会显示在日志与拦截提示里，"
                                   L"也参与安装拦截的目录名匹配。",
                    MB_OK | MB_ICONWARNING);
        SetFocus(state->nameEdit);
        return false;
    }

    // 没有匹配条件的规则在服务端永远不会命中，用户却会以为"已经防住了"——
    // 这里必须挡住，而不是保存一个沉默的无效规则。
    if (draft.processNames.empty() && draft.paths.empty() && draft.signers.empty() &&
        draft.hashes.empty()) {
        ShowMessage(state->window,
                    L"这条规则没有任何匹配条件。\n\n请至少填写一项：进程名、路径、签名者或 SHA-256。",
                    MB_OK | MB_ICONWARNING);
        SetFocus(state->processEdit);
        return false;
    }

    state->draft = std::move(draft);
    return true;
}

LRESULT CALLBACK EditDialogProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<EditDialogState*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message) {
        case WM_NCCREATE: {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(window, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            return DefWindowProcW(window, message, wParam, lParam);
        }

        case WM_CREATE:
            if (state != nullptr) {
                state->window = window;
                CreateEditControls(state, window);
                PopulateEditDialog(state);
                SetFocus(state->nameEdit);
            }
            return 0;

        case WM_COMMAND:
            if (state == nullptr) {
                break;
            }
            switch (LOWORD(wParam)) {
                case kIdEditOk:
                    if (ReadBackEditDialog(state)) {
                        state->confirmed = true;
                        DestroyWindow(window);
                    }
                    return 0;
                case kIdEditCancel:
                    DestroyWindow(window);
                    return 0;
                default:
                    break;
            }
            break;

        case WM_CLOSE:
            DestroyWindow(window);
            return 0;

        default:
            break;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

// 以模态方式运行编辑对话框（禁用属主窗口 + 本地消息循环）。
// 不用 DialogBoxParam：那需要 .rc 资源模板，本项目零资源文件。
bool RunRuleEditDialog(HWND owner, RuleDraft& draft) {
    EditDialogState state;
    state.draft = draft;
    state.font = g_manager.font;

    const DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    const DWORD exStyle = WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT;

    RECT desired{0, 0, kEditWidth, kEditHeight};
    AdjustWindowRectEx(&desired, style, FALSE, exStyle);

    RECT ownerRect{};
    GetWindowRect(owner, &ownerRect);
    const int width = desired.right - desired.left;
    const int height = desired.bottom - desired.top;
    const int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - width) / 2;
    const int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - height) / 2;

    EnableWindow(owner, FALSE);
    HWND window = CreateWindowExW(exStyle, kEditClassName, L"编辑规则", style, x, y, width, height,
                                  owner, nullptr, GetModuleHandleW(nullptr), &state);
    if (window == nullptr) {
        EnableWindow(owner, TRUE);
        return false;
    }

    ShowWindow(window, SW_SHOW);

    MSG message{};
    while (IsWindow(window) && GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);

    if (state.confirmed) {
        draft = state.draft;
    }
    return state.confirmed;
}

// ---------------------------------------------------------------------------
// 保存
// ---------------------------------------------------------------------------

// 写文件（UTF-8 + BOM，与 ConfigManager 生成默认配置的编码一致，
// 避免用户用记事本打开时中文乱码）
bool WriteConfigBytes(const std::wstring& path, const std::string& bytes, std::wstring& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = L"写入配置失败（错误码 " + std::to_wstring(GetLastError()) + L"）";
        return false;
    }

    DWORD written = 0;
    const bool ok =
        WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != FALSE;
    CloseHandle(file);

    if (!ok) {
        error = L"写入配置失败（错误码 " + std::to_wstring(GetLastError()) + L"）";
        return false;
    }
    return true;
}

// 提权写入：把内容先写到临时文件，再用一个提升的 cmd.exe 拷回目标路径。
//
// 为什么需要：config.json 由服务（LocalSystem）创建，ACL 给普通用户只有读取权限，
// 而前端刻意以普通用户运行（不允许整个界面常驻高权限）。
// UAC 只在"保存"这一个动作上出现，与"启动/停止服务"按钮的处理方式一致。
bool WriteConfigElevated(const std::string& bytes, std::wstring& error) {
    wchar_t tempDirectory[MAX_PATH] = {};
    if (GetTempPathW(_countof(tempDirectory), tempDirectory) == 0) {
        error = L"无法定位临时目录";
        return false;
    }
    const std::wstring tempFile =
        std::wstring(tempDirectory) + L"GuardDog_config_" + std::to_wstring(GetCurrentProcessId()) +
        L".json";

    if (!WriteConfigBytes(tempFile, bytes, error)) {
        return false;
    }

    const std::wstring parameters =
        L"/c copy /y \"" + tempFile + L"\" \"" + g_manager.configPath + L"\"";

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    info.lpFile = L"cmd.exe";
    info.lpParameters = parameters.c_str();
    info.nShow = SW_HIDE;

    if (!ShellExecuteExW(&info)) {
        const DWORD lastError = GetLastError();
        DeleteFileW(tempFile.c_str());
        if (lastError == ERROR_CANCELLED) {
            error = L"已取消管理员授权，配置未保存。";
        } else {
            error = L"无法发起提权写入（错误码 " + std::to_wstring(lastError) + L"）";
        }
        return false;
    }

    DWORD exitCode = 1;
    if (info.hProcess != nullptr) {
        WaitForSingleObject(info.hProcess, 30000);
        GetExitCodeProcess(info.hProcess, &exitCode);
        CloseHandle(info.hProcess);
    }
    DeleteFileW(tempFile.c_str());

    if (exitCode != 0) {
        error = L"提权写入失败（copy 退出码 " + std::to_wstring(exitCode) + L"）";
        return false;
    }
    return true;
}

void PerformSave() {
    // ---- 1) 用界面上的内容重建 blacklist，其余字段保持原样 ----
    JsonValue blacklist = JsonValue::MakeArray();
    for (const RuleDraft& rule : g_manager.rules) {
        JsonValue item = JsonValue::MakeObject();
        item.Set(L"name", JsonValue::MakeString(rule.name));
        item.Set(L"enabled", JsonValue::MakeBool(rule.enabled));
        item.Set(L"process_names", MakeStringArray(rule.processNames));
        item.Set(L"paths", MakeStringArray(rule.paths));
        item.Set(L"signers", MakeStringArray(rule.signers));
        item.Set(L"hashes", MakeStringArray(rule.hashes));
        blacklist.PushBack(std::move(item));
    }
    g_manager.root.Set(L"blacklist", std::move(blacklist));

    JsonValue settings = g_manager.root.Find(L"settings");
    if (!settings.IsObject()) {
        settings = JsonValue::MakeObject();
    }
    settings.Set(L"block_install",
                 JsonValue::MakeBool(SendMessageW(g_manager.blockInstallCheck, BM_GETCHECK, 0, 0) ==
                                     BST_CHECKED));
    settings.Set(L"clean_legacy_on_start",
                 JsonValue::MakeBool(SendMessageW(g_manager.cleanLegacyCheck, BM_GETCHECK, 0, 0) ==
                                     BST_CHECKED));
    settings.Set(L"remove_whole_directory",
                 JsonValue::MakeBool(SendMessageW(g_manager.removeWholeCheck, BM_GETCHECK, 0, 0) ==
                                     BST_CHECKED));
    settings.Set(L"destroy_pe_header",
                 JsonValue::MakeBool(SendMessageW(g_manager.destroyPeCheck, BM_GETCHECK, 0, 0) ==
                                     BST_CHECKED));
    g_manager.root.Set(L"settings", std::move(settings));

    // ---- 2) 序列化（带 BOM）----
    const std::string utf8 = g_manager.root.SerializeUtf8(2);
    std::string bytes;
    bytes.reserve(utf8.size() + 3);
    bytes.append("\xEF\xBB\xBF", 3);
    bytes += utf8;

    // ---- 3) 写入。服务创建的配置文件默认不允许普通用户写，失败时走提权路径 ----
    std::wstring error;
    if (!WriteConfigBytes(g_manager.configPath, bytes, error)) {
        const std::wstring prompt =
            L"保存配置需要管理员授权。\n\n"
            L"原因：配置文件由防护服务（系统账户）创建，当前用户对它只有读取权限。\n\n"
            L"是否继续？确认后会弹出 UAC 授权窗口，仅用于写入这一个文件。";
        if (MessageBoxW(g_manager.window, prompt.c_str(), L"GuardDog 规则管理",
                        MB_OKCANCEL | MB_ICONQUESTION | MB_SETFOREGROUND) != IDOK) {
            return;
        }
        if (!WriteConfigElevated(bytes, error)) {
            ShowMessage(g_manager.window, error, MB_OK | MB_ICONWARNING);
            return;
        }
    }

    // ---- 4) 让服务立即用上新配置 ----
    // 服务本身会在 1 秒内检测到文件变更并热重载，这里额外发 RELOAD 是为了
    // 拿到"确实加载成功"的反馈——如果新配置有错，此刻就能告诉用户，
    // 而不是等到下一次拦截失败才发现。
    std::wstring response;
    std::wstring message = L"配置已保存。";
    if (IpcClient::Send(L"RELOAD", response)) {
        message += L"\n\n服务反馈：" + ResponseText(response);
    } else {
        message += L"\n\n防护服务当前未运行，新配置将在服务启动时自动加载。";
    }
    ShowMessage(g_manager.window, message, MB_OK | MB_ICONINFORMATION);

    // ---- 5) 重新从磁盘加载：把服务端归一化后的结果（如哈希格式）反映到界面上 ----
    if (LoadConfigIntoState()) {
        RefreshRuleList();
    }
}

// ---------------------------------------------------------------------------
// 管理窗口
// ---------------------------------------------------------------------------

void CreateManagerControls(HWND window) {
    const HFONT font = g_manager.font;

    HWND intro = CreateWindowExW(
        0, L"STATIC",
        L"任一维度命中即拦截（各维度之间是“或”）；白名单优先于黑名单。\r\n"
        L"安装拦截说明：新装入的目录名与“规则名”互为子串时也会命中，便于规则名直接描述软件名称。",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, 8, kManagerWidth - 24, 36, window, nullptr, nullptr,
        nullptr);
    SendMessageW(intro, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

    g_manager.list = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 12, 48,
        kManagerWidth - 24, 300, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdRuleList)), nullptr, nullptr);
    SendMessageW(g_manager.list, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    ListView_SetExtendedListViewStyle(
        g_manager.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

    for (int column = 0; column < kListColumnCount; ++column) {
        LVCOLUMNW spec{};
        spec.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        spec.pszText = const_cast<wchar_t*>(kListColumnTitles[column]);
        spec.cx = kListColumnWidths[column];
        spec.iSubItem = column;
        ListView_InsertColumn(g_manager.list, column, &spec);
    }

    const auto addButton = [&](const wchar_t* text, int id, int x, int y, int width) {
        HWND button = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      x, y, width, 34, window,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr,
                                      nullptr);
        SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return button;
    };

    const int buttonY = kManagerHeight - 46;
    addButton(L"新增规则", kIdAddRule, 12, buttonY, 96);
    addButton(L"编辑", kIdEditRule, 114, buttonY, 80);
    addButton(L"删除", kIdDeleteRule, 200, buttonY, 80);
    addButton(L"启用 / 停用", kIdToggleRule, 286, buttonY, 110);
    addButton(L"关闭", kIdCloseManager, kManagerWidth - 216, buttonY, 96);
    addButton(L"保存并生效", kIdSaveRules, kManagerWidth - 114, buttonY, 102);

    const auto addCheck = [&](const wchar_t* text, int id, int x, int y, int width) {
        HWND checkbox = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                                             BS_AUTOCHECKBOX,
                                        x, y, width, 22, window,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr,
                                        nullptr);
        SendMessageW(checkbox, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        return checkbox;
    };

    const int checkY = kManagerHeight - 118;
    g_manager.blockInstallCheck = addCheck(L"阻止软件安装（新装入黑名单目录时立即清理）", kIdBlockInstall,
                                           12, checkY, 470);
    g_manager.cleanLegacyCheck = addCheck(L"启动时强制清理已存在的目标软件（存量清理）", kIdCleanLegacy,
                                          500, checkY, 470);
    g_manager.removeWholeCheck = addCheck(L"整套处置（连同目录下其他可执行文件一并清除）",
                                          kIdRemoveWhole, 12, checkY + 30, 470);
    g_manager.destroyPeCheck = addCheck(L"删除失败时破坏 PE 头（让程序永久无法运行）", kIdDestroyPe,
                                        500, checkY + 30, 470);
}

void HandleManagerCommand(HWND window, int id) {
    switch (id) {
        case kIdAddRule: {
            RuleDraft draft;
            if (RunRuleEditDialog(window, draft)) {
                g_manager.rules.push_back(std::move(draft));
                RefreshRuleList();
            }
            return;
        }

        case kIdEditRule: {
            const int index = SelectedRuleIndex();
            if (index < 0 || static_cast<size_t>(index) >= g_manager.rules.size()) {
                ShowMessage(window, L"请先在列表中选择一条规则。", MB_OK | MB_ICONWARNING);
                return;
            }
            RuleDraft draft = g_manager.rules[static_cast<size_t>(index)];
            if (RunRuleEditDialog(window, draft)) {
                g_manager.rules[static_cast<size_t>(index)] = std::move(draft);
                RefreshRuleList();
            }
            return;
        }

        case kIdDeleteRule: {
            const int index = SelectedRuleIndex();
            if (index < 0 || static_cast<size_t>(index) >= g_manager.rules.size()) {
                ShowMessage(window, L"请先在列表中选择要删除的规则。", MB_OK | MB_ICONWARNING);
                return;
            }
            const RuleDraft& rule = g_manager.rules[static_cast<size_t>(index)];
            const std::wstring prompt = L"确定删除规则「" + rule.name +
                                        L"」吗？\n\n删除后需点击「保存并生效」才会写入配置文件。";
            if (MessageBoxW(window, prompt.c_str(), L"GuardDog 规则管理",
                            MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES) {
                g_manager.rules.erase(g_manager.rules.begin() + index);
                RefreshRuleList();
            }
            return;
        }

        case kIdToggleRule: {
            const int index = SelectedRuleIndex();
            if (index < 0 || static_cast<size_t>(index) >= g_manager.rules.size()) {
                ShowMessage(window, L"请先在列表中选择一条规则。", MB_OK | MB_ICONWARNING);
                return;
            }
            RuleDraft& rule = g_manager.rules[static_cast<size_t>(index)];
            rule.enabled = !rule.enabled;
            RefreshRuleList();
            // 保持选中行，连续切换多条规则时不用反复点选
            ListView_SetItemState(g_manager.list, index, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            return;
        }

        case kIdSaveRules:
            PerformSave();
            return;

        case kIdCloseManager:
            DestroyWindow(window);
            return;

        default:
            return;
    }
}

LRESULT CALLBACK ManagerWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            g_manager.window = window;
            CreateManagerControls(window);
            if (LoadConfigIntoState()) {
                RefreshRuleList();
            } else {
                ShowMessage(window, g_manager.loadError, MB_OK | MB_ICONWARNING);
            }
            return 0;

        case WM_COMMAND:
            HandleManagerCommand(window, LOWORD(wParam));
            return 0;

        case WM_NOTIFY: {
            auto* header = reinterpret_cast<NMHDR*>(lParam);
            if (header != nullptr && header->idFrom == kIdRuleList &&
                header->code == NM_DBLCLK) {
                // 双击 = 编辑，符合列表类界面的通行操作习惯
                HandleManagerCommand(window, kIdEditRule);
            }
            return 0;
        }

        case WM_CLOSE:
            DestroyWindow(window);
            return 0;

        default:
            return DefWindowProcW(window, message, wParam, lParam);
    }
}

bool RegisterDialogClasses() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSEXW managerClass{};
    managerClass.cbSize = sizeof(managerClass);
    managerClass.lpfnWndProc = ManagerWindowProc;
    managerClass.hInstance = GetModuleHandleW(nullptr);
    managerClass.lpszClassName = kManagerClassName;
    managerClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    managerClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);

    WNDCLASSEXW editClass = managerClass;
    editClass.lpfnWndProc = EditDialogProc;
    editClass.lpszClassName = kEditClassName;

    if (RegisterClassExW(&managerClass) == 0 || RegisterClassExW(&editClass) == 0) {
        return false;
    }
    registered = true;
    return true;
}

} // namespace

void ShowRuleManagerDialog(HWND owner, HFONT uiFont) {
    // ListView 属于通用控件；manifest 里已声明 comctl32 v6，
    // 调用方必须显式初始化对应类目，否则创建窗口会失败
    INITCOMMONCONTROLSEX commonControls{};
    commonControls.dwSize = sizeof(commonControls);
    commonControls.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&commonControls);

    if (!RegisterDialogClasses()) {
        ShowMessage(owner, L"注册窗口类失败，无法打开规则管理界面。", MB_OK | MB_ICONWARNING);
        return;
    }

    g_manager.font = uiFont;
    g_manager.window = nullptr;

    const DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    const DWORD exStyle = WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT;

    RECT desired{0, 0, kManagerWidth, kManagerHeight};
    AdjustWindowRectEx(&desired, style, FALSE, exStyle);

    RECT ownerRect{};
    GetWindowRect(owner, &ownerRect);
    const int width = desired.right - desired.left;
    const int height = desired.bottom - desired.top;
    const int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - width) / 2;
    const int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - height) / 2;

    EnableWindow(owner, FALSE);
    HWND window = CreateWindowExW(exStyle, kManagerClassName, L"GuardDog 规则管理", style, x, y,
                                  width, height, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (window == nullptr) {
        EnableWindow(owner, TRUE);
        ShowMessage(owner, L"创建规则管理窗口失败。", MB_OK | MB_ICONWARNING);
        return;
    }

    ShowWindow(window, SW_SHOW);

    // 模态消息循环：与编辑对话框同一手法（禁用属主 + 本地循环）
    MSG message{};
    while (IsWindow(window) && GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    g_manager.window = nullptr;
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

} // namespace GuardDog