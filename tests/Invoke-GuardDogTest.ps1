<#
.SYNOPSIS
    GuardDog 集成测试脚本：模拟流氓软件的各种"复活"手法，验证 GuardDog 能否清干净。

.DESCRIPTION
    覆盖四个场景：
      1. RunKeyAndGuard    -- Run 键自启动 + 守护进程（被杀后 3 秒重拉目标）
      2. ServiceWithRecovery -- 服务自启动 + 自动重启策略（"服务停不掉"）
      3. WmiSubscription   -- WMI 永久事件订阅自启动（很多工具漏掉的一类）
      4. FileDisposal      -- 文件处置（进程终止 + 源文件删除）

    脚本会用 Add-Type 现场生成两个测试用的 .NET 可执行文件，因此不需要 C++ 编译器。
    测试期间会临时替换 GuardDog 配置，结束后自动还原。

.PARAMETER Scenario
    要运行的场景，默认全部。

.PARAMETER WorkDir
    测试工作目录（默认 %TEMP%\GuardDogTest）。

.PARAMETER SkipConfigSwap
    不替换 GuardDog 配置（适用于你已经手工配置好测试规则的场景）。

.EXAMPLE
    # 以管理员身份运行全部场景
    .\Invoke-GuardDogTest.ps1

.EXAMPLE
    # 只测守护进程场景，并保留测试产物以便排查
    .\Invoke-GuardDogTest.ps1 -Scenario RunKeyAndGuard -WorkDir D:\gdtest
#>

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('RunKeyAndGuard', 'ServiceWithRecovery', 'WmiSubscription', 'FileDisposal', 'All')]
    [string[]]$Scenario = @('All'),

    [string]$WorkDir = (Join-Path $env:TEMP 'GuardDogTest'),

    [switch]$SkipConfigSwap
)

$ErrorActionPreference = 'Stop'

$script:ConfigPath = 'C:\ProgramData\GuardDog\config.json'
$script:LogPath    = 'C:\ProgramData\GuardDog\logs\guarddog.log'
$script:Results    = @()
$script:ConfigBackup = $null

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Add-Result([string]$Scenario, [string]$Check, [bool]$Passed, [string]$Detail = '') {
    $script:Results += [pscustomobject]@{
        Scenario = $Scenario
        Check    = $Check
        Passed   = $Passed
        Detail   = $Detail
    }
    $color = if ($Passed) { 'Green' } else { 'Red' }
    $mark  = if ($Passed) { 'PASS' } else { 'FAIL' }
    Write-Host ("  [{0}] {1}{2}" -f $mark, $Check, $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor $color
}

function Test-ProcessRunning([string]$Name) {
    return (Get-Process -Name $Name -ErrorAction SilentlyContinue) -ne $null
}

function Wait-Until([scriptblock]$Condition, [int]$TimeoutSeconds = 30, [int]$IntervalMs = 500) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds $IntervalMs
    }
    return $false
}

function Get-LogTail([int]$Lines = 40) {
    if (-not (Test-Path $script:LogPath)) { return @() }
    return Get-Content $script:LogPath -Tail $Lines -ErrorAction SilentlyContinue
}

function Stop-TestProcessSafely([string]$Name) {
    Get-Process -Name $Name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 测试程序生成（用 Add-Type 现场编译，避免依赖 C++ 工具链）
# ---------------------------------------------------------------------------

function New-TestExecutables {
    Write-Step "生成测试用可执行文件到 $WorkDir"

    if (-not (Test-Path $WorkDir)) {
        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    }

    $targetPath = Join-Path $WorkDir 'gd_test_target.exe'
    $guardPath  = Join-Path $WorkDir 'gd_test_guard.exe'

    # 目标：常驻空转
    $targetSource = @'
using System;
using System.Threading;
public class GDTarget {
    public static void Main() {
        while (true) { Thread.Sleep(1000); }
    }
}
'@

    # 守护进程：目标消失后 3 秒内重新拉起它
    $guardSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
public class GDGuard {
    public static void Main() {
        string dir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        string target = Path.Combine(dir, "gd_test_target.exe");
        Launch(target, dir);
        while (true) {
            Thread.Sleep(3000);
            bool alive = false;
            foreach (Process p in Process.GetProcessesByName("gd_test_target")) {
                alive = true; break;
            }
            if (!alive) { Launch(target, dir); }
        }
    }
    static void Launch(string exe, string workDir) {
        try {
            ProcessStartInfo info = new ProcessStartInfo(exe);
            info.WorkingDirectory = workDir;
            info.UseShellExecute = false;
            Process.Start(info);
        } catch { }
    }
}
'@

    Add-Type -TypeDefinition $targetSource -OutputAssembly $targetPath -OutputType WindowsApplication
    Add-Type -TypeDefinition $guardSource  -OutputAssembly $guardPath  -OutputType WindowsApplication

    # 母本副本：GuardDog 的处置流程会删除目标文件，
    # 后续场景必须从母本重新复制一份，否则会拿"文件不存在"去测服务启动，
    # 得到一堆假阳性的"通过"。
    $masterPath = Join-Path $WorkDir 'gd_test_target_master.exe'
    Copy-Item $targetPath $masterPath -Force

    Write-Host "  已生成 $targetPath" -ForegroundColor DarkGray
    Write-Host "  已生成 $guardPath" -ForegroundColor DarkGray
    Write-Host "  已保留母本 $masterPath" -ForegroundColor DarkGray

    return @{ Target = $targetPath; Guard = $guardPath; Master = $masterPath }
}

# 从母本恢复测试目标文件。
# 先确保没有残留进程占用它——守护进程会周期性尝试拉起目标，
# 期间会短暂持有文件句柄，直接复制会失败。
function Reset-TestTarget([hashtable]$Exes) {
    if (-not (Test-Path $Exes.Master)) {
        return $false
    }

    Stop-TestProcessSafely 'gd_test_guard'
    Stop-TestProcessSafely 'gd_test_target'
    Start-Sleep -Milliseconds 500

    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        try {
            Copy-Item $Exes.Master -Destination $Exes.Target -Force -ErrorAction Stop
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

# ---------------------------------------------------------------------------
# 配置切换
# ---------------------------------------------------------------------------

function Set-TestConfig([string]$TargetExePath) {
    Write-Step '写入测试配置（黑名单指向测试目标）'

    if (-not $SkipConfigSwap) {
        if (Test-Path $script:ConfigPath) {
            $script:ConfigBackup = Get-Content $script:ConfigPath -Raw -Encoding UTF8
        }

        $config = @"
{
  "blacklist": [
    {
      "name": "GuardDog 集成测试目标",
      "enabled": true,
      "process_names": ["gd_test_target.exe"]
    }
  ],
  "whitelist": {
    "process_names": ["explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "dwm.exe"],
    "paths": ["C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*", "C:\\Windows\\WinSxS\\*"],
    "signers": ["Microsoft Corporation", "Microsoft Windows"],
    "hashes": []
  },
  "settings": {
    "poll_interval_ms": 500,
    "wmi_enabled": true,
    "destroy_pe_header": true,
    "delay_delete_on_reboot": true,
    "observe_after_kill_seconds": 300,
    "clean_wmi_subscriptions": true,
    "clean_legacy_on_start": false,
    "log_level": "debug"
  }
}
"@
        [System.IO.File]::WriteAllText($script:ConfigPath, $config, (New-Object System.Text.UTF8Encoding($true)))
        Start-Sleep -Seconds 2   # 等服务热重载
        Write-Host '  测试配置已生效（原配置已备份，脚本结束时会还原）' -ForegroundColor DarkGray
    }
    else {
        Write-Host '  已跳过配置替换（-SkipConfigSwap）' -ForegroundColor DarkGray
    }
}

function Restore-OriginalConfig {
    if ($script:ConfigBackup -and -not $SkipConfigSwap) {
        Write-Step '还原原始配置'
        [System.IO.File]::WriteAllText($script:ConfigPath, $script:ConfigBackup,
                                       (New-Object System.Text.UTF8Encoding($true)))
        Start-Sleep -Seconds 2
        Write-Host '  已还原' -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# 场景 1：Run 键自启动 + 守护进程
# ---------------------------------------------------------------------------

function Invoke-RunKeyAndGuard([hashtable]$Exes) {
    Write-Step '场景 1：Run 键自启动 + 守护进程'

    Reset-TestTarget $Exes | Out-Null   # 从母本恢复（上一场景可能已删掉目标文件）

    $runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty -Path $runKey -Name 'GuardDogTestEntry' -Value $Exes.Target -Type String
    Write-Host "  已写入 Run 键：GuardDogTestEntry = $($Exes.Target)" -ForegroundColor DarkGray

    Start-Process -FilePath $Exes.Guard | Out-Null
    Write-Host '  已启动守护进程（它会拉起目标）' -ForegroundColor DarkGray

    $targetGone = Wait-Until { -not (Test-ProcessRunning 'gd_test_target') } -TimeoutSeconds 20
    $guardGone  = Wait-Until { -not (Test-ProcessRunning 'gd_test_guard') }  -TimeoutSeconds 20

    $valueGone = Wait-Until {
        $null -eq (Get-ItemProperty -Path $runKey -Name 'GuardDogTestEntry' -ErrorAction SilentlyContinue)
    } -TimeoutSeconds 10

    Add-Result 'RunKeyAndGuard' '目标进程被终止' $targetGone
    Add-Result 'RunKeyAndGuard' '守护进程被连带终止' $guardGone
    Add-Result 'RunKeyAndGuard' 'Run 键自启动项被删除' $valueGone

    $log = Get-LogTail 60
    $hasBreak = ($log | Select-String '判定为守护进程并连带处置').Count -gt 0
    Add-Result 'RunKeyAndGuard' '日志记录了守护进程识别' $hasBreak

    # 复活测试：再次启动守护进程，应被再次清除
    if ($targetGone) {
        Stop-TestProcessSafely 'gd_test_guard'
        Start-Sleep -Seconds 1
        Reset-TestTarget $Exes | Out-Null   # 上一轮处置已删掉目标文件，先恢复
        Start-Process -FilePath $Exes.Guard | Out-Null
        $recleared = Wait-Until { -not (Test-ProcessRunning 'gd_test_target') } -TimeoutSeconds 20
        Add-Result 'RunKeyAndGuard' '复活后被再次清除' $recleared
    }
}

# ---------------------------------------------------------------------------
# 场景 2：服务自启动 + 自动重启策略
# ---------------------------------------------------------------------------

function Invoke-ServiceWithRecovery([hashtable]$Exes) {
    Write-Step '场景 2：服务自启动 + 自动重启策略'

    $serviceName = 'GuardDogTestSvc'
    & sc.exe delete $serviceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    Reset-TestTarget $Exes | Out-Null   # 服务启动需要目标文件真实存在

    & sc.exe create $serviceName binPath= $Exes.Target start= auto DisplayName= 'GuardDog 测试服务' | Out-Null
    Start-Sleep -Seconds 1

    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName")) {
        Add-Result 'ServiceWithRecovery' '测试服务已创建' $false '服务创建失败，后续检查无意义'
        return
    }

    & sc.exe failure $serviceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    & sc.exe start $serviceName 2>&1 | Out-Null
    Write-Host '  已创建服务并设置"失败后自动重启"策略' -ForegroundColor DarkGray

    $targetGone = Wait-Until { -not (Test-ProcessRunning 'gd_test_target') } -TimeoutSeconds 25
    Add-Result 'ServiceWithRecovery' '服务启动的目标进程被终止' $targetGone

    # 服务应被禁用或删除
    $disabled = Wait-Until {
        $item = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $true }          # 已被彻底删除
        return $item.Start -eq 4                        # 4 = 已禁用
    } -TimeoutSeconds 20
    Add-Result 'ServiceWithRecovery' '服务被禁用或删除' $disabled

    $log = Get-LogTail 80
    $clearedFailure = ($log | Select-String '已清除服务恢复策略').Count -gt 0
    Add-Result 'ServiceWithRecovery' '日志记录了恢复策略清除' $clearedFailure

    & sc.exe delete $serviceName 2>&1 | Out-Null
}

# ---------------------------------------------------------------------------
# 场景 3：WMI 永久事件订阅
# ---------------------------------------------------------------------------

function Invoke-WmiSubscription([hashtable]$Exes) {
    Write-Step '场景 3：WMI 永久事件订阅'

    $consumerName = 'GuardDogTestConsumer'
    $filterName   = 'GuardDogTestFilter'

    Reset-TestTarget $Exes | Out-Null   # 需要真实文件存在才能启动目标

    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'" |
        Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'" |
        Remove-WmiObject -ErrorAction SilentlyContinue

    $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name           = $filterName
        EventNamespace = 'root\cimv2'
        QueryLanguage  = 'WQL'
        Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_OperatingSystem'"
    }
    $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
        Name                = $consumerName
        CommandLineTemplate = $Exes.Target
    }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $filter
        Consumer = $consumer
    } | Out-Null

    Write-Host '  已创建 WMI 永久事件订阅（指向测试目标）' -ForegroundColor DarkGray

    # 触发一次处置，让 GuardDog 去清理订阅
    Start-Process -FilePath $Exes.Target | Out-Null
    Wait-Until { -not (Test-ProcessRunning 'gd_test_target') } -TimeoutSeconds 20 | Out-Null

    $consumerGone = Wait-Until {
        $null -eq (Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'" -ErrorAction SilentlyContinue)
    } -TimeoutSeconds 20

    $filterGone = Wait-Until {
        $null -eq (Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue)
    } -TimeoutSeconds 20

    Add-Result 'WmiSubscription' 'EventConsumer 被删除' $consumerGone
    Add-Result 'WmiSubscription' 'EventFilter 被删除' $filterGone

    $log = Get-LogTail 80
    $logOk = ($log | Select-String '已删除订阅绑定').Count -gt 0
    Add-Result 'WmiSubscription' '日志记录了绑定清理' $logOk
}

# ---------------------------------------------------------------------------
# 场景 4：文件处置
# ---------------------------------------------------------------------------

function Invoke-FileDisposal([hashtable]$Exes) {
    Write-Step '场景 4：文件处置（终止 + 删除源文件）'

    Reset-TestTarget $Exes | Out-Null

    $target = $Exes.Target
    if (-not (Test-Path $target)) {
        Add-Result 'FileDisposal' '测试目标文件存在' $false "未找到 $target"
        return
    }

    Start-Process -FilePath $target | Out-Null
    Write-Host '  已启动测试目标' -ForegroundColor DarkGray

    $gone = Wait-Until { -not (Test-ProcessRunning 'gd_test_target') } -TimeoutSeconds 20
    Add-Result 'FileDisposal' '进程被终止' $gone

    $deleted = Wait-Until { -not (Test-Path $target) } -TimeoutSeconds 15
    Add-Result 'FileDisposal' '源文件被删除或已报废' $deleted

    $log = Get-LogTail 60
    $disposeLogged = ($log | Select-String '文件处置').Count -gt 0
    Add-Result 'FileDisposal' '日志记录了文件处置' $disposeLogged
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'GuardDog 集成测试' -ForegroundColor Yellow
Write-Host "工作目录：$WorkDir"

# 前置检查：GuardDog 服务必须在运行
$svc = Get-Service -Name GuardDogService -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Host '[错误] 未找到 GuardDogService 服务，请先执行：GuardDogService.exe install' -ForegroundColor Red
    exit 2
}
if ($svc.Status -ne 'Running') {
    Write-Host "[信息] 服务当前状态为 $($svc.Status)，尝试启动..."
    Start-Service -Name GuardDogService
    Start-Sleep -Seconds 3
}

$exes = New-TestExecutables
Set-TestConfig $exes.Target

$scenarios = if ($Scenario -contains 'All') {
    @('RunKeyAndGuard', 'ServiceWithRecovery', 'WmiSubscription', 'FileDisposal')
} else {
    $Scenario
}

try {
    foreach ($name in $scenarios) {
        switch ($name) {
            'RunKeyAndGuard'       { Invoke-RunKeyAndGuard $exes }
            'ServiceWithRecovery'  { Invoke-ServiceWithRecovery $exes }
            'WmiSubscription'      { Invoke-WmiSubscription $exes }
            'FileDisposal'         { Invoke-FileDisposal $exes }
        }
    }
}
finally {
    # 无论中途是否出错，都要清理现场并还原配置
    Write-Step '清理测试现场'
    Stop-TestProcessSafely 'gd_test_target'
    Stop-TestProcessSafely 'gd_test_guard'
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
        -Name 'GuardDogTestEntry' -ErrorAction SilentlyContinue
    Restore-OriginalConfig
}

Write-Host ''
Write-Host '===== 测试摘要 =====' -ForegroundColor Yellow
$passed = ($script:Results | Where-Object { $_.Passed }).Count
$total  = $script:Results.Count
$script:Results | Format-Table -AutoSize Scenario, Check, Passed, Detail
Write-Host "结果：$passed / $total 项通过" -ForegroundColor $(if ($passed -eq $total) { 'Green' } else { 'Red' })

if ($passed -ne $total) { exit 1 }