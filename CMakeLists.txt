cmake_minimum_required(VERSION 3.20)

project(GuardDog
    VERSION 0.1.0
    DESCRIPTION "GuardDog - 纯用户态防流氓软件防护工具"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# 构建环境约束
# 只支持 MSVC + x64：代码重度依赖 Windows 特有 API（服务/注册表/WMI/PE），
# 用 MinGW 会产生大量无关兼容问题，直接在这里挡掉，避免误报编译错误。
# ---------------------------------------------------------------------------
if(NOT MSVC)
    message(FATAL_ERROR "GuardDog 仅支持 MSVC 构建（Visual Studio 2022 + Windows 10/11 SDK）")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "GuardDog 仅支持 x64 目标（Windows 10/11 x64）")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
endif()

# 统一产物目录：build/bin，方便后续安装脚本 / 测试脚本定位 exe
set(GUARDDOG_OUTPUT_DIR ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${GUARDDOG_OUTPUT_DIR})
foreach(cfg IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg} ${GUARDDOG_OUTPUT_DIR})
endforeach()

# ---------------------------------------------------------------------------
# 全局编译选项
# UNICODE/_UNICODE：全程宽字符 API，避免 A/W 混用导致的中文路径问题
# NOMINMAX：禁止 windows.h 定义 min/max 宏，否则与 <algorithm> 冲突
# /utf-8：源码与执行字符集都是 UTF-8，保证中文字面量正确
# ---------------------------------------------------------------------------
add_compile_definitions(
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /MP /EHsc)

# ---------------------------------------------------------------------------
# GuardDogCore：所有可执行目标共享的静态库
# 后续批次（监控、自启动清理、文件处置）继续挂到这里
# ---------------------------------------------------------------------------
add_library(GuardDogCore STATIC
    src/Core/Json.cpp
    src/Core/FileInfo.cpp
    src/Core/Logger.cpp
    src/Core/ConfigManager.cpp
    src/Core/Matcher.cpp
    src/Monitor/ProcessKiller.cpp
    src/Monitor/ProcessPoller.cpp
    src/Monitor/WmiMonitor.cpp
    src/AutoStart/AutoStartTypes.cpp
    src/AutoStart/AutoStartScanner.cpp
    src/AutoStart/RegistryRun.cpp
    src/AutoStart/StartupFolder.cpp
    src/AutoStart/ServiceCleaner.cpp
    src/AutoStart/TaskCleaner.cpp
    src/AutoStart/WmiSubscriptionCleaner.cpp
    src/AutoStart/IfeoCleaner.cpp
    src/AutoStart/AppInitCleaner.cpp
    src/AutoStart/WinlogonCleaner.cpp
)

target_include_directories(GuardDogCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# bcrypt   —— SHA-256（文件哈希维度）
# crypt32  —— 解析 PKCS#7 签名、提取签名者证书、catalog 查找
# wintrust —— WinVerifyTrust 签名策略校验
# wbemuuid —— WMI 的 CLSID_WbemLocator / IID_IWbemLocator 等 GUID 定义
# shell32  —— SHGetKnownFolderPath（启动文件夹定位）、IShellLink（解析 .lnk）
# ole32    —— COM 初始化与实例化
# oleaut32 —— BSTR 与 VARIANT 操作（WMI 属性读取）
# uuid     —— IID_IShellLinkW / IID_IPersistFile 等接口 IID
target_link_libraries(GuardDogCore PUBLIC
    bcrypt crypt32 wintrust wbemuuid shell32 ole32 oleaut32 uuid)

# ---------------------------------------------------------------------------
# GuardDogService：服务主程序
# 使用 WIN32 子系统（需求：无窗口运行）；由于入口函数是 wmain，
# 必须显式指定 CRT 入口点 wmainCRTStartup，否则链接器会去找 WinMain 而失败。
# ---------------------------------------------------------------------------
add_executable(GuardDogService WIN32
    src/Service/main.cpp
    src/Service/ServiceInstaller.cpp
)

target_link_libraries(GuardDogService PRIVATE GuardDogCore)
set_target_properties(GuardDogService PROPERTIES LINK_FLAGS "/ENTRY:wmainCRTStartup")

# 后续批次目标（占位说明，勿删）：
#   GuardDogWatchdog.exe —— 批次 6 看门狗
#   GuardDogUI.exe       —— 批次 6 之后托盘 UI