#include "TinyVT.h"

#define EPT_ENTRIES_PER_TABLE 512ULL
#define EPT_GB_SIZE (1ULL << 30)
#define EPT_2MB_SIZE (1ULL << 21)
#define EPT_LARGE_PAGE (1ULL << 7)
#define EPT_NON_LEAF_FLAGS 0x7ULL
#define EPT_POOL_TAG 'tpEL'
#define EPT_MAX_PHYSICAL_ADDRESS (1ULL << 48)

Eptp EptP = { 0 };
PCHAR EptMem = 0;
BOOLEAN UseEpt = TRUE;

static PVOID EptAllocationBase = NULL;
static ULONGLONG EptMaxPhysicalAddress = 0;
static ULONG_PTR EptPml4Count = 0;
static ULONG_PTR EptOneGbPageCount = 0;
static ULONGLONG EptLeafFlags = 0;
static KSPIN_LOCK EptSplitLock;

typedef struct _EPT_SPLIT_PAGE {
	struct _EPT_SPLIT_PAGE* Next;
	EptCommonEntry* PageDirectoryEntry;
	EptCommonEntry* PageTable;
} EPT_SPLIT_PAGE, * PEPT_SPLIT_PAGE;

static PEPT_SPLIT_PAGE volatile EptSplitPages = NULL;

static BOOLEAN GetMaximumPhysicalAddress(ULONGLONG* maximumAddress)
{
	PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
	if (!ranges)
		return FALSE;

	ULONGLONG maximum = 0;
	BOOLEAN valid = TRUE;
	for (PPHYSICAL_MEMORY_RANGE range = ranges;
		range->NumberOfBytes.QuadPart != 0;
		++range) {
		ULONGLONG base = (ULONGLONG)range->BaseAddress.QuadPart;
		ULONGLONG size = (ULONGLONG)range->NumberOfBytes.QuadPart;
		if (base > MAXULONGLONG - size) {
			valid = FALSE;
			break;
		}

		ULONGLONG end = base + size;
		if (end > maximum)
			maximum = end;
	}

	ExFreePool(ranges);
	if (!valid || maximum == 0)
		return FALSE;

	*maximumAddress = maximum;
	return TRUE;
}

static EptCommonEntry* GetPdeByPhyAddr(ULONG_PTR address)
{
	if (!EptMem || (ULONGLONG)address >= EptMaxPhysicalAddress)
		return NULL;

	ULONG_PTR oneGbIndex = address >> 30;
	if (oneGbIndex >= EptOneGbPageCount)
		return NULL;

	ULONG_PTR tablePageIndex = 1 + EptPml4Count + oneGbIndex;
	ULONG_PTR* pageDirectory = (ULONG_PTR*)(EptMem + tablePageIndex * PAGE_SIZE);
	ULONG_PTR pageDirectoryIndex = (address >> 21) & (EPT_ENTRIES_PER_TABLE - 1);
	return (EptCommonEntry*)&pageDirectory[pageDirectoryIndex];
}

static PEPT_SPLIT_PAGE FindSplitPage(EptCommonEntry* pageDirectoryEntry)
{
	for (PEPT_SPLIT_PAGE page = EptSplitPages; page; page = page->Next) {
		if (page->PageDirectoryEntry == pageDirectoryEntry)
			return page;
	}
	return NULL;
}

EptCommonEntry* GetPteByPhyAddr(ULONG_PTR address)
{
	EptCommonEntry* pageDirectoryEntry = GetPdeByPhyAddr(address);
	if (!pageDirectoryEntry)
		return NULL;

	ULONGLONG entry = (ULONGLONG)InterlockedCompareExchange64(
		(volatile LONG64*)&pageDirectoryEntry->all, 0, 0);
	if (entry & EPT_LARGE_PAGE)
		return NULL;

	PEPT_SPLIT_PAGE splitPage = FindSplitPage(pageDirectoryEntry);
	if (!splitPage)
		return NULL;

	ULONG_PTR pageTableIndex = (address >> 12) & (EPT_ENTRIES_PER_TABLE - 1);
	return &splitPage->PageTable[pageTableIndex];
}

BOOLEAN EnsureEptPteForPhyAddr(ULONG_PTR address)
{
	EptCommonEntry* pageDirectoryEntry = GetPdeByPhyAddr(address);
	if (!pageDirectoryEntry)
		return FALSE;

	ULONGLONG currentEntry = (ULONGLONG)InterlockedCompareExchange64(
		(volatile LONG64*)&pageDirectoryEntry->all, 0, 0);
	if (!(currentEntry & EPT_LARGE_PAGE))
		return FindSplitPage(pageDirectoryEntry) != NULL;

	EptCommonEntry* pageTable = (EptCommonEntry*)kmalloc(PAGE_SIZE);
	if (!pageTable)
		return FALSE;

	PEPT_SPLIT_PAGE splitPage = (PEPT_SPLIT_PAGE)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(EPT_SPLIT_PAGE), EPT_POOL_TAG);
	if (!splitPage) {
		kfree(pageTable);
		return FALSE;
	}
	RtlZeroMemory(splitPage, sizeof(*splitPage));

	ULONGLONG largePageBase = (ULONGLONG)address & ~(EPT_2MB_SIZE - 1);
	for (ULONG_PTR index = 0; index < EPT_ENTRIES_PER_TABLE; ++index) {
		pageTable[index].all = largePageBase + index * PAGE_SIZE + EptLeafFlags;
	}

	BOOLEAN installed = FALSE;
	KIRQL oldIrql;
	KeAcquireSpinLock(&EptSplitLock, &oldIrql);
	currentEntry = (ULONGLONG)InterlockedCompareExchange64(
		(volatile LONG64*)&pageDirectoryEntry->all, 0, 0);
	if (currentEntry & EPT_LARGE_PAGE) {
		splitPage->PageDirectoryEntry = pageDirectoryEntry;
		splitPage->PageTable = pageTable;
		splitPage->Next = EptSplitPages;
		EptSplitPages = splitPage;

		ULONGLONG pageTablePhysicalAddress = MmGetPhysicalAddress(pageTable).QuadPart;
		InterlockedExchange64((volatile LONG64*)&pageDirectoryEntry->all,
			(LONG64)(pageTablePhysicalAddress | EPT_NON_LEAF_FLAGS));
		installed = TRUE;
	}
	else {
		installed = FindSplitPage(pageDirectoryEntry) != NULL;
	}
	KeReleaseSpinLock(&EptSplitLock, oldIrql);

	if (!installed) {
		kfree(pageTable);
		ExFreePoolWithTag(splitPage, EPT_POOL_TAG);
	}
	return installed;
}

BOOLEAN InitEpt()
{
	if (!UseEpt)
		return FALSE;

	KeInitializeSpinLock(&EptSplitLock);

	ULONGLONG maximumAddress = 0;
	if (!GetMaximumPhysicalAddress(&maximumAddress)) {
		Log("Unable to query physical memory ranges");
		return FALSE;
	}
	if (maximumAddress > EPT_MAX_PHYSICAL_ADDRESS) {
		Log("Physical address range exceeds the 48-bit EPT address space");
		return FALSE;
	}

	ULONGLONG eptCapabilities = __readmsr(MsrVmxEptVpidCap);
	if (!(eptCapabilities & (1ULL << 6)) || !(eptCapabilities & (1ULL << 16))) {
		Log("CPU does not support 4-level EPT with 2-MB pages");
		return FALSE;
	}

	ULONG memoryType;
	if (eptCapabilities & (1ULL << 14))
		memoryType = kWriteBack;
	else if (eptCapabilities & (1ULL << 8))
		memoryType = kUncacheable;
	else {
		Log("CPU reports no supported EPT memory type");
		return FALSE;
	}
	EptLeafFlags = EPT_NON_LEAF_FLAGS | ((ULONGLONG)memoryType << 3);

	ULONGLONG oneGbPageCount = (maximumAddress + EPT_GB_SIZE - 1) >> 30;
	ULONGLONG pml4Count = (oneGbPageCount + EPT_ENTRIES_PER_TABLE - 1) / EPT_ENTRIES_PER_TABLE;
	ULONGLONG tablePageCount = 1 + pml4Count + oneGbPageCount;
	if (tablePageCount > MAXULONG_PTR / PAGE_SIZE) {
		Log("EPT page table allocation size overflow");
		return FALSE;
	}

	SIZE_T tableBytes = (SIZE_T)(tablePageCount * PAGE_SIZE);
	if (tableBytes > MAXULONG_PTR - (PAGE_SIZE - 1)) {
		Log("EPT page table allocation size overflow");
		return FALSE;
	}

	SIZE_T allocationBytes = tableBytes + PAGE_SIZE - 1;
	EptAllocationBase = ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationBytes, EPT_POOL_TAG);
	if (!EptAllocationBase) {
		Log("EPT page table allocation failed (%llu bytes)", (ULONGLONG)tableBytes);
		return FALSE;
	}

	ULONG_PTR alignedAddress = ((ULONG_PTR)EptAllocationBase + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	EptMem = (PCHAR)alignedAddress;
	RtlZeroMemory(EptMem, tableBytes);
	EptMaxPhysicalAddress = maximumAddress;
	EptPml4Count = (ULONG_PTR)pml4Count;
	EptOneGbPageCount = (ULONG_PTR)oneGbPageCount;

	ULONG_PTR* pml4 = (ULONG_PTR*)EptMem;
	PCHAR pdptPages = EptMem + PAGE_SIZE;
	PCHAR pageDirectoryPages = pdptPages + EptPml4Count * PAGE_SIZE;

	for (ULONG_PTR pml4Index = 0; pml4Index < EptPml4Count; ++pml4Index) {
		ULONG_PTR* pdpt = (ULONG_PTR*)(pdptPages + pml4Index * PAGE_SIZE);
		pml4[pml4Index] = MmGetPhysicalAddress(pdpt).QuadPart | EPT_NON_LEAF_FLAGS;

		for (ULONG_PTR pdptIndex = 0; pdptIndex < EPT_ENTRIES_PER_TABLE; ++pdptIndex) {
			ULONG_PTR oneGbIndex = pml4Index * EPT_ENTRIES_PER_TABLE + pdptIndex;
			if (oneGbIndex >= EptOneGbPageCount)
				break;

			ULONG_PTR* pageDirectory = (ULONG_PTR*)(pageDirectoryPages + oneGbIndex * PAGE_SIZE);
			pdpt[pdptIndex] = MmGetPhysicalAddress(pageDirectory).QuadPart | EPT_NON_LEAF_FLAGS;

			for (ULONG_PTR pageDirectoryIndex = 0;
				pageDirectoryIndex < EPT_ENTRIES_PER_TABLE;
				++pageDirectoryIndex) {
				ULONGLONG physicalBase = ((ULONGLONG)oneGbIndex << 30) |
					((ULONGLONG)pageDirectoryIndex << 21);
				pageDirectory[pageDirectoryIndex] = physicalBase | EptLeafFlags | EPT_LARGE_PAGE;
			}
		}
	}

	EptP.all = MmGetPhysicalAddress(pml4).QuadPart |
		(ULONGLONG)memoryType | (3ULL << 3);
	return TRUE;
}

VOID DestroyEpt()
{
	PEPT_SPLIT_PAGE splitPage = EptSplitPages;
	EptSplitPages = NULL;
	while (splitPage) {
		PEPT_SPLIT_PAGE next = splitPage->Next;
		kfree(splitPage->PageTable);
		ExFreePoolWithTag(splitPage, EPT_POOL_TAG);
		splitPage = next;
	}

	if (EptAllocationBase)
		ExFreePoolWithTag(EptAllocationBase, EPT_POOL_TAG);

	EptAllocationBase = NULL;
	EptMem = NULL;
	EptP.all = 0;
	EptMaxPhysicalAddress = 0;
	EptPml4Count = 0;
	EptOneGbPageCount = 0;
	EptLeafFlags = 0;
}
