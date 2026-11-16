#include"HOOK.h"
#include"nmd_assembly.h"

// Linked list head for storing EPT hook info (doubly linked).
EptHookInfo HidePageEntry = { 0 };

// NOTE: SSDT-based hooking has been removed. Callers should now use
// MmGetSystemRoutineAddress (or symbol resolution) to obtain the target
// function address, then call EptHOOK(FunAddr, FakeAddr) directly.
// The original GetSSDT() / GetSsdtFunAddr() required per-version
// adaptation (especially under Win11 22H2 + KVA Shadow), which was
// fragile. The "by-address" API is version-agnostic and more flexible.

// Compute the smallest instruction-boundary length >= 12 bytes.
ULONG_PTR GetWriteCodeLen(PVOID buffer)
{
	const char* const buffer_end = (char*)buffer + 45;

	nmd_x86_instruction instruction;
	char formatted_instruction[128];

	for (size_t i = 0; i < 45; i += instruction.length)
	{
		if (!nmd_decode_x86((char*)buffer + i, buffer_end - ((char*)buffer + i), &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_MINIMAL))
			break;
#pragma warning(push)
#pragma warning(disable:4245)
		nmd_format_x86(&instruction, formatted_instruction, NMD_X86_INVALID_RUNTIME_ADDRESS, NMD_X86_FORMAT_FLAGS_DEFAULT);
#pragma warning(pop)
		if (i >= 12) return i;
	}

	return 0;
}

// Lookup HOOK info by physical address (matches both Fake and Real pages).
PEptHookInfo GetHookInfoByPA(ULONG_PTR physAddr)
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return NULL;

	physAddr &= 0xFFFFFFFFFFFFF000;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);
		if ((physAddr == pEntry->FakePagePhyAddr || physAddr == pEntry->RealPagePhyAddr) && physAddr)
			return pEntry;
	}
	return NULL;
}

// Lookup HOOK info by function virtual address.
PEptHookInfo GetHookInfoByFunAddr(ULONG_PTR vaAddr)
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return NULL;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);
		if (vaAddr == pEntry->OriginalFunAddr && vaAddr)
			return pEntry;
	}
	return NULL;
}

PVOID EptHOOK(ULONG_PTR FunAddr, PVOID FakeFun)
{
	PVOID OriginalFunHeadCode = 0;
	/*
	Use this pattern for trampoline back to original:
	  push FakeAddr
	  ret
	NOT using `jmp qword ptr [***]` style because the indirect address
	would itself live in the hooked page and trigger EPT violations
	recursively on every fetch.
	*/
	UCHAR JmpFakeAddr[] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x50\xC3";
	UCHAR JmpOriginalFun[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

	if (GetHookInfoByFunAddr(FunAddr)) return NULL;

	// Patch forward-jump with FakeFun address.
	memcpy(JmpFakeAddr + 2, &FakeFun, 8);

	// Build backward-jump to original function (skip our overwritten head).
	ULONG_PTR WriteLen = GetWriteCodeLen((PVOID)FunAddr);
	ULONG_PTR JmpOriginalAddr = FunAddr + WriteLen;
	memcpy(JmpOriginalFun + 6, &JmpOriginalAddr, 8);

	// Clone original 4KB page.
	ULONG_PTR fakePage = (ULONG_PTR)kmalloc(PAGE_SIZE);
	RtlCopyMemory((PVOID)fakePage, (PVOID)(FunAddr & 0xFFFFFFFFFFFFF000), PAGE_SIZE);

	// Build "original head + jump back" buffer for the fake function to call.
	OriginalFunHeadCode = kmalloc(WriteLen + 14);
	RtlFillMemory(OriginalFunHeadCode, WriteLen + 14, 0x90);
	memcpy(OriginalFunHeadCode, (PVOID)FunAddr, WriteLen);
	memcpy((PCHAR)(OriginalFunHeadCode)+WriteLen, JmpOriginalFun, 14);

	// Patch the cloned page: NOP the original head, write forward-jump to FakeFun.
	ULONG_PTR offset = FunAddr - (FunAddr & 0xFFFFFFFFFFFFF000);
	RtlFillMemory((PVOID)(fakePage + offset), WriteLen, 0x90);
	memcpy((PVOID)(fakePage + offset), &JmpFakeAddr, 12);

	// Initialize list head lazily.
	if (HidePageEntry.list.Flink == NULL) {
		InitializeListHead(&HidePageEntry.list);
	}

	// Record hook info.
	PEptHookInfo hidePage = (PEptHookInfo)kmalloc(sizeof(EptHookInfo));
	hidePage->FakePageVaAddr = fakePage;
	hidePage->FakePagePhyAddr = MmGetPhysicalAddress((PVOID)fakePage).QuadPart & 0xFFFFFFFFFFFFF000;
	hidePage->RealPagePhyAddr = MmGetPhysicalAddress((PVOID)(FunAddr & 0xFFFFFFFFFFFFF000)).QuadPart;
	hidePage->OriginalFunAddr = FunAddr;
	hidePage->OriginalFunHeadCode = (ULONG_PTR)OriginalFunHeadCode;

	if (!EnsureEptPteForPhyAddr(hidePage->RealPagePhyAddr)) {
		kfree(hidePage);
		kfree(OriginalFunHeadCode);
		kfree((PVOID)fakePage);
		return NULL;
	}

	InsertTailList(&HidePageEntry.list, &hidePage->list);

	// VMCALL into HOST to flip the EPT PTE.
	AsmVmxCall(CallEptHook, (ULONG_PTR)hidePage);

	return OriginalFunHeadCode;
}

VOID EptUnHOOK(ULONG_PTR FunAddr)
{
	PEptHookInfo hookInfo = GetHookInfoByFunAddr(FunAddr);
	if (!hookInfo) return;

	AsmVmxCall(CallEptUnHook, (ULONG_PTR)hookInfo);

	kfree((PVOID)hookInfo->OriginalFunHeadCode);
	kfree((PVOID)hookInfo->FakePageVaAddr);
}

// Remove all installed EPT hooks.
VOID DestroyEptHook()
{
	if (HidePageEntry.list.Flink == NULL || IsListEmpty(&HidePageEntry.list))
		return;

	for (PLIST_ENTRY pListEntry = HidePageEntry.list.Flink; pListEntry != &HidePageEntry.list; pListEntry = pListEntry->Flink)
	{
		PEptHookInfo pEntry = CONTAINING_RECORD(pListEntry, EptHookInfo, list);
		EptUnHOOK(pEntry->OriginalFunAddr);
	}
}
