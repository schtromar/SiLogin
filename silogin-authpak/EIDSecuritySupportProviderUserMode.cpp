// User-mode SSP negotiation is deliberately disabled in this AP-only scaffold.
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <NTSecAPI.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <NTSecPKG.h>

extern "C" NTSTATUS NTAPI SpUserModeInitialize(ULONG lsaVersion,
    PULONG packageVersion, PSECPKG_USER_FUNCTION_TABLE* tables, PULONG tableCount)
{
    UNREFERENCED_PARAMETER(lsaVersion);
    if (packageVersion) *packageVersion = 0;
    if (tables) *tables = nullptr;
    if (tableCount) *tableCount = 0;
    return STATUS_NOT_SUPPORTED;
}
