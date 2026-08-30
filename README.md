# LinVT

轻量级 VT 框架与 EPT 无痕 HOOK。
作者:泠
测试环境:Windows 11 22H2 (Build 22621) / Intel i7-8550U / ~32 GB

## 简介

本项目基于 Intel VT-x + EPT(Extended Page Tables)实现了一个 Windows 内核
无痕 HOOK 框架。EPT HOOK 不修改目标函数首字节,因此可绕过绝大多数对函数
头部的 CRC / 签名校验,这是"无痕"的含义。

项目包含三个变体,按学习递进设计:

| 目录 | 说明 |
|------|------|
| `NoEPT/` | 仅 VT 框架骨架,不开 EPT,用于理解 VMLAUNCH / VMCS / VM-Exit |
| `UseEPT/` | VT + EPT,验证 EPT 页表通路,但尚未挂钩 |
| `EptHook/` | 完整 EPT 无痕 HOOK 实现,自带 NtOpenProcess 演示 |

## 已实现的 Hook 示例

| 目标函数 | 文件 | 用途 |
|----------|------|------|
| `NtOpenProcess` | `EptHook/BlogVT/test.cpp` | 统计句柄打开次数 |
| `NtReadVirtualMemory` | `EptHook/BlogVT/HookReadMemory.cpp` | 监控所有进程内存读取,记录调用方 PID / 句柄 / 基址 / 字节数 / 状态码 |

`NtReadVirtualMemory` 是反外挂与内存保护的核心 hook 点 —— 所有读进程内存的工具
(Cheat Engine、Process Hacker、调试器、dump 工具、游戏外挂)最终都会落到这里。

## 主要 API (EptHook 变体)

```c
// 按函数地址挂钩(不依赖 SSDT)
PVOID EptHOOK(ULONG_PTR FunAddr, PVOID FakeAddr);
VOID  EptUnHOOK(ULONG_PTR FunAddr);
VOID  DestroyEptHook();
```

调用方自行用 `MmGetSystemRoutineAddress` 或符号解析拿到目标函数地址,再
传入 `EptHOOK` 即可挂钩任意 4 KB 对齐代码页。

## 部署 (Win11 22H2)

```cmd
REM 1. 启用测试签名(管理员 PowerShell)
bcdedit /set testsigning on
bcdedit /set nointegritychecks on

REM 2. 重启后加载驱动
sc create LinVT type=kernel binPath="C:\path\BlogVT.sys"
sc start LinVT

REM 3. 卸载
sc stop LinVT
sc delete LinVT
```

**注意**:
- Win11 22H2 默认开启 HVCI / 内核隔离,需要在"设置 → Windows 安全中心
  → 设备安全 → 内核隔离"中关闭"内存完整性",否则测试签名驱动仍会被拒。
- 若系统为 Secure Boot 启用状态,且 bcdedit 被锁,需先进 BIOS 关闭
  Secure Boot 再操作。
- 云端 VM (如 Google Teemo) 若不开放"内核隔离"开关,只能换宿主机或绕过
  Secure Boot 才能加载。

## 调试输出

驱动以 `DbgPrintEx` 输出,前缀 `[LinVT]`。用 DebugView (Dbgview.exe) 抓取,
记得勾选"Capture Kernel"。

## 钩挂能力速览

挂钩目标可以是任意 4 KB 对齐代码页、任意 nt/win32k 导出函数、驱动 I/O
Dispatch 例程、内核回调表、MSR/LSTAR/IDT 等结构所在页。挂钩后可实现进程
监控、文件/注册表过滤、反调试、反外挂、教学研究等用途。

## 限制

- 不能挂钩被 PatchGuard 主动清零的地址
- 钩子函数不能调用 PG 监控的 API,否则蓝屏
- 云 VM 上 EPT 物理页可能因 hypervisor 重置而失效
