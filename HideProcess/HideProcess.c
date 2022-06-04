#include "HideProcess.h"

NTKERNELAPI PUCHAR PsGetProcessImageFileName(__in PEPROCESS Process);

ULONG GetActiveProcessLinksOffset();
PEPROCESS ForceFindProcessByName(PCHAR szName);
HANDLE FindProcessIdByName(PCHAR szName);


PEPROCESS ForceFindProcessByName(PCHAR szName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS pEprocess = NULL;
    PUCHAR ProcessPathName = NULL;

    for (size_t i = 4; i < 0x10000000; i += 4)
    {
        status = PsLookupProcessByProcessId((HANDLE)i, &pEprocess);
        if (!NT_SUCCESS(status))
        {
            continue;
        }

        ProcessPathName = PsGetProcessImageFileName(pEprocess);
        if (!ProcessPathName)
        {
            continue;
        }

        DbgPrint("%s \r\n", ProcessPathName);

        if (strstr(ProcessPathName, szName) != 0)
        {
            return pEprocess;
        }
        ObfDereferenceObject(pEprocess);
    }
    return NULL;
}


HANDLE FindProcessIdByName(PCHAR szName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;
    PUCHAR ProcessName = NULL;
    PLIST_ENTRY pHead = NULL;
    PLIST_ENTRY pNode = NULL;
    
    ULONG64 ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
    //KdPrint(("ActiveProcessLinksOffset = %llX\n", ActiveProcessLinksOffset));
    if (!ActiveProcessLinksOffset)
    {
        KdPrint(("GetActiveProcessLinksOffset failed\n"));
        return NULL;
    }
    Process = PsGetCurrentProcess();

    pHead = (PLIST_ENTRY)((ULONG64)Process + ActiveProcessLinksOffset);
    pNode = pHead;

    do
    {
        Process = (PEPROCESS)((ULONG64)pNode - ActiveProcessLinksOffset);
        ProcessName = PsGetProcessImageFileName(Process);
        //KdPrint(("%s\n", ProcessName));
        if (strstr(szName, ProcessName))
        {
            return *(HANDLE*)((ULONG64)pNode - 8);
        }

        pNode = pNode->Flink;
    } while (pNode != pHead);

    return NULL;
}


ULONG GetActiveProcessLinksOffset()
{
    UNICODE_STRING FunName = { 0 };
    RtlInitUnicodeString(&FunName, L"PsGetProcessId");

/*
.text:000000014007E054                   PsGetProcessId  proc near
.text:000000014007E054
.text:000000014007E054 48 8B 81 80 01 00+                mov     rax, [rcx+180h]
.text:000000014007E054 00
.text:000000014007E05B C3                                retn
.text:000000014007E05B                   PsGetProcessId  endp
*/

    PUCHAR pfnPsGetProcessId = (PUCHAR)MmGetSystemRoutineAddress(&FunName);
    if (pfnPsGetProcessId && MmIsAddressValid(pfnPsGetProcessId) && MmIsAddressValid(pfnPsGetProcessId + 0x7))
    {
        for (size_t i = 0; i < 0x7; i++)
        {
            if (pfnPsGetProcessId[i] == 0x48 && pfnPsGetProcessId[i + 1] == 0x8B)
            {
                return *(PULONG)(pfnPsGetProcessId + i + 3) + 8;
            }
        }
    }
    return 0;
}


//Win10-11 Only
ULONG GetProtectionOffset()
{
    UNICODE_STRING FunName = { 0 };
    RtlInitUnicodeString(&FunName, L"PsIsProtectedProcess");

/*
.text:0000000140203410                   PsIsProtectedProcess proc near          ; CODE XREF: NtQueryInformationProcess+735¡ýp
.text:0000000140203410                                                           ; PspAllocateProcess+1E3B¡ýp
.text:0000000140203410                                                           ; DATA XREF: ...
.text:0000000140203410 F6 81 7A 08 00 00+                test    byte ptr [rcx+87Ah], 7
.text:0000000140203410 07
.text:0000000140203417 B8 00 00 00 00                    mov     eax, 0
.text:000000014020341C 0F 97 C0                          setnbe  al
.text:000000014020341F C3                                retn
.text:000000014020341F                   PsIsProtectedProcess endp
*/

    PUCHAR pfnPsIsProtectedProcess = (PUCHAR)MmGetSystemRoutineAddress(&FunName);
    if (pfnPsIsProtectedProcess && MmIsAddressValid(pfnPsIsProtectedProcess) && MmIsAddressValid(pfnPsIsProtectedProcess + 0x10))
    {
        for (size_t i = 0; i < 0x10; i++)
        {
            if (pfnPsIsProtectedProcess[i] == 0xF6 && pfnPsIsProtectedProcess[i + 1] == 0x81 && pfnPsIsProtectedProcess[i + 7] == 0xB8)
            {
                return *(PULONG)(pfnPsIsProtectedProcess + i + 2);
            }
        }
    }
    return 0;
}


//Win10-11 Only
NTSTATUS SetProtectionStatus(PEPROCESS Process)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ProtectionOffset = 0;

    if (!MmIsAddressValid(Process))
    {
        return STATUS_UNSUCCESSFUL;
    }
    ProtectionOffset = GetProtectionOffset();
    if (!ProtectionOffset)
    {
        return STATUS_UNSUCCESSFUL;
    }
    *(ULONG*)((ULONG64)Process + ProtectionOffset) = 0x40000051;
    return status;
}


NTSTATUS HideProcessByProcessId(HANDLE ProcessId)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN bFlag = FALSE;
    PEPROCESS Process = NULL;

    ULONG ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
    if (!ActiveProcessLinksOffset)
    {
        KdPrint(("GetActiveListOffset failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("PsLookupProcessByProcessId failed\n"));
        return status;
    }
    KdPrint(("EPROCESS = %p\n", Process));

    KIRQL irql = KeRaiseIrqlToDpcLevel();

    //SetProtectionStatus(Process);

    *(UCHAR*)((ULONG64)Process - 0x15) = 0x4;   //ObjectHeader.Flags.KernelOnlyAccess = 1

    //RemoveEntryList((PLIST_ENTRY)((PUCHAR)Process + ActiveProcessLinksOffset));
    //InitializeListHead((PLIST_ENTRY)((PUCHAR)Process + ActiveProcessLinksOffset));  //SelfConnected

    *(PULONG64)((PUCHAR)Process + ActiveProcessLinksOffset - 8) = 0x0;    //ProcessId 
    //Will trigger BSOD if pid not exist on Win7

    KeLowerIrql(irql);

    ObDereferenceObject(Process);

    return status;
}


NTSTATUS HideProcessByName(PCHAR szName)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE ProcessId = NULL;

    ProcessId = FindProcessIdByName(szName);
    if (!ProcessId)
    {
        KdPrint(("FindProcessByName failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    HideProcessByProcessId(ProcessId);

    return status;
}


