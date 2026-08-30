#include "HOOK.h"

// NtReadVirtualMemory is the kernel-side entry point that backs
// ReadProcessMemory / NtWow64ReadVirtualMemory64 / toolhelp ReadProcessMemory
// etc. Hooking it intercepts every attempt by user-mode code (or by other
// kernel drivers) to read another process's address space -- which is the
// fundamental operation of memory scanners (CheatEngine, Process Hacker, ...),
// game cheats, and memory-dump malware.
//
// Signature (per ntifs.h / ntddk.h):
//   NTSTATUS NtReadVirtualMemory(
//       HANDLE      ProcessHandle,     // target process (or NtCurrentProcess())
//       PVOID       BaseAddress,       // VA inside target
//       PVOID       Buffer,            // VA in caller
//       SIZE_T      NumberOfBytesToRead,
//       PSIZE_T     NumberOfBytesRead);
typedef NTSTATUS(*pNtReadVirtualMemory)(
	HANDLE      ProcessHandle,
	PVOID       BaseAddress,
	PVOID       Buffer,
	SIZE_T      NumberOfBytesToRead,
	PSIZE_T     NumberOfBytesRead
);

static pNtReadVirtualMemory g_OriginalNtReadVirtualMemory = NULL;
static ULONG_PTR            g_NtReadVirtualMemoryAddr    = 0;

// Stats: count of invocations and total bytes requested.
static volatile LONG    g_RvmCount      = 0;
static volatile LONGLONG g_RvmTotalBytes = 0;

// -----------------------------------------------------------------------------
// Hook implementation
// -----------------------------------------------------------------------------
NTSTATUS MyNtReadVirtualMemory(
	HANDLE   ProcessHandle,
	PVOID    BaseAddress,
	PVOID    Buffer,
	SIZE_T   NumberOfBytesToRead,
	PSIZE_T  NumberOfBytesRead)
{
	// Call the original (backed by trampoline allocated by EptHOOK).
	NTSTATUS status = g_OriginalNtReadVirtualMemory(
		ProcessHandle, BaseAddress, Buffer,
		NumberOfBytesToRead, NumberOfBytesRead);

	LONG hit = InterlockedIncrement(&g_RvmCount);
	InterlockedAdd64(&g_RvmTotalBytes, (LONGLONG)NumberOfBytesToRead);

	// Sample log every 50 calls to avoid DebugView flooding.
	if ((hit % 50) == 0) {
		HANDLE callerPid = PsGetCurrentProcessId();
		Log(
			"[RVM] hit=%ld pid=%p handle=%p base=%p bytes=%llu status=0x%08X totalCalls=%ld totalBytes=%lld",
			hit,
			callerPid,
			ProcessHandle,
			BaseAddress,
			(ULONGLONG)NumberOfBytesToRead,
			(ULONG)status,
			hit,
			g_RvmTotalBytes
		);
	}

	return status;
}

// -----------------------------------------------------------------------------
// Install / Uninstall
// -----------------------------------------------------------------------------
EXTERN_C BOOLEAN InstallReadMemoryHook()
{
	UNICODE_STRING name = RTL_CONSTANT_STRING(L"NtReadVirtualMemory");
	ULONG_PTR fnAddr = (ULONG_PTR)MmGetSystemRoutineAddress(&name);
	if (!fnAddr) {
		Log("[HookRVM] Cannot resolve NtReadVirtualMemory, skipping");
		return FALSE;
	}

	g_NtReadVirtualMemoryAddr = fnAddr;
	Log("[HookRVM] NtReadVirtualMemory at %p, installing EPT hook", fnAddr);

	g_OriginalNtReadVirtualMemory =
		(pNtReadVirtualMemory)EptHOOK(fnAddr, MyNtReadVirtualMemory);

	if (!g_OriginalNtReadVirtualMemory) {
		g_NtReadVirtualMemoryAddr = 0;
		Log("[HookRVM] EptHOOK failed");
		return FALSE;
	}
	Log("[HookRVM] EPT hook installed successfully");
	return TRUE;
}

EXTERN_C VOID UninstallReadMemoryHook()
{
	if (g_NtReadVirtualMemoryAddr) {
		EptUnHOOK(g_NtReadVirtualMemoryAddr);
		g_NtReadVirtualMemoryAddr    = 0;
		g_OriginalNtReadVirtualMemory = NULL;
		Log("[HookRVM] EPT hook removed");
	}
}
