#include <ntifs.h>

NTSTATUS HideProcessByName(PCHAR szName);
NTSTATUS HideProcessByProcessId(HANDLE ProcessId);
