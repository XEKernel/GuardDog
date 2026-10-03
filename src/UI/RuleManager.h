#pragma once

#include <windows.h>

namespace GuardDog {

// 规则管理窗口：用可视化界面增删改黑名单规则与关键防护开关，
// 保存时回写 config.json 并触发服务热重载。
//
// 为什么写配置的职责放在 UI 而不是服务：
// "要防护什么软件"属于用户意图，用户应以普通用户身份编辑；服务只读取与热重载。
// 若在 IPC 上开放"写配置"命令，等于让任何能连上管道的本机进程都能改写防护策略——
// 那比不设防更糟，因为被改过的配置看起来仍是"GuardDog 在保护"。
//
// 配置文件位于 C:\ProgramData（由服务以 SYSTEM 身份创建，普通用户只有读权限），
// 保存时若直接写入失败会请求一次 UAC 提权完成写入。
//
// uiFont 由调用方传入（主窗口共用同一字体对象，避免重复创建与字体不一致）。
void ShowRuleManagerDialog(HWND owner, HFONT uiFont);

} // namespace GuardDog