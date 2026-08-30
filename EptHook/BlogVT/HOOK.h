#pragma once
#include"TinyVT.h"

// Doubly linked list node for storing one EPT hook entry.
typedef struct _EptHookInfo
{
	ULONG_PTR RealPagePhyAddr;

	ULONG_PTR FakePagePhyAddr;
	ULONG_PTR FakePageVaAddr;

	ULONG_PTR OriginalFunAddr;
	ULONG_PTR OriginalFunHeadCode;

	LIST_ENTRY list;
} EptHookInfo, * PEptHookInfo;

// NOTE: SSDT-based hooking has been removed. The original
// SYSTEM_SERVICE_TABLE struct, GetSSDT() and GetSsdtFunAddr()
// required per-version adaptation (especially under Win11 22H2 +
// KVA Shadow). Callers now resolve the target function address
// themselves (e.g. via MmGetSystemRoutineAddress) and pass it
// directly to EptHOOK().

// Lookup hook info by physical address (matches both Fake and Real pages).
PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr);
// Lookup hook info by function virtual address.
PEptHookInfo GetHookInfoByFunAddr(ULONG_PTR vaAddr);

// Install an EPT no-trace hook on FunAddr, redirecting to FakeAddr.
// Returns a pointer to a buffer containing the original function head
// followed by a jmp back to FunAddr + head-length (for FakeAddr to call).
PVOID EptHOOK(ULONG_PTR FunAddr, PVOID FakeAddr);
VOID EptUnHOOK(ULONG_PTR FunAddr);
VOID DestroyEptHook();
