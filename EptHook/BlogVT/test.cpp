#include"HOOK.h"

// NtOpenProcess signature. Resolved at runtime via MmGetSystemRoutineAddress,
// so we no longer depend on SSDT (which differs across Windows builds and
// is hidden under KVA Shadow on Win10 1903+ / Win11).
typedef NTSTATUS(*pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

static pNtOpenProcess g_OriginalNtOpenProcess = NULL;
static volatile LONG  g_NtOpenProcessHitCount = 0;

// Hooked NtOpenProcess: counts invocations and forwards to the original.
NTSTATUS MyNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	LONG hit = InterlockedIncrement(&g_NtOpenProcessHitCount);
	if ((hit % 100) == 0) {
		Log("HOOK NtOpenProcess hit count: %ld", hit);
	}
	return g_OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// Install the EPT hook on NtOpenProcess. Called from DriverEntry after VT
// has started on every CPU.
EXTERN_C VOID HookTest()
{
	UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"NtOpenProcess");
	ULONG_PTR fnAddr = (ULONG_PTR)MmGetSystemRoutineAddress(&funcName);
	if (!fnAddr) {
		Log("[HookTest] Cannot resolve NtOpenProcess, skipping hook");
		return;
	}
	Log("[HookTest] NtOpenProcess at %p, installing EPT hook", fnAddr);
	g_OriginalNtOpenProcess = (pNtOpenProcess)EptHOOK(fnAddr, MyNtOpenProcess);
	if (!g_OriginalNtOpenProcess) {
		Log("[HookTest] EptHOOK failed");
	}
}
