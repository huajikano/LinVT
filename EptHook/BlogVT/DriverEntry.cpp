#include"TinyVT.h"
#include"HOOK.h"
#include<Ndis.h>

TinyVT* AllVT[128] = {0};

EXTERN_C VOID LoadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//��ȡ��ǰCPU���ĵĺ���
	ULONG index = KeGetCurrentProcessorIndex();
	if (CheckVTSupport() && CheckVTEnable())
	{
		TinyVT* tinyVt = new TinyVT(index);
		if (tinyVt->StartVT()) {
			AllVT[index] = tinyVt;
			Log("[CPU:%d]����VT�ɹ�", index);
		}
		else {
			Log("[CPU:%d]����VTʧ��",index);
		}
		
	}
	else {
		Log("[CPU:%d]��֧�����⻯", index);
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

EXTERN_C VOID UnloadVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	int index = KeGetCurrentProcessorIndex();

	if (AllVT[index] && AllVT[index]->isEnable) {
		AsmVmxCall(CallExitVT, NULL);
	}

	if (AllVT[index]) {
		delete AllVT[index];
		AllVT[index] = NULL;
	}
	Log("[CPU:%d]VT���˳�", index);

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}


EXTERN_C VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	//������HOOK����VT
	UninstallReadMemoryHook();
	//DestroyEptHook();
	//��ʱ��һ���������
	NdisStallExecution(50);

	KeGenericCallDpc(UnloadVT, NULL);

	//��ʱ��һ��VT�˳����
	NdisStallExecution(50);
	if (EptMem) {
		kfree(EptMem);
		EptMem = 0;
	}

	Log("����ж��");
}

EXTERN_C VOID HookTest();
EXTERN_C BOOLEAN InstallReadMemoryHook();
EXTERN_C VOID UninstallReadMemoryHook();

//��C���Է�ʽ������C++Ϊ֧�ֺ������أ��������ᱻ�ı䣬���±��벻ͨ��
EXTERN_C VOID DriverEntry(PDRIVER_OBJECT driver, UNICODE_STRING path)
{
	//�ò����Ĳ�����UNREFERENCED_PARAMETER�����������򱨴���Ҳ������->C/C++ ->��������Ϊ���󡱹ص������Ｐ֮��������ﶼ����
	UNREFERENCED_PARAMETER(path);
	driver->DriverUnload = DriverUnload;

	if (!InitEpt()) {
		UseEpt = FALSE;
		Log("Ept��ʼ��ʧ��!");
	}

	KeGenericCallDpc(LoadVT, NULL);

	//��һ�����к��ļ�����VT
	NdisStallExecution(50);
	HookTest();
	InstallReadMemoryHook();
	
	Log("��������");
}