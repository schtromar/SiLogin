#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <NTSecAPI.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <NTSecPKG.h>
#include "../libsilogin/LsaAuthenticationProtocol.h"

extern "C" {
NTSTATUS NTAPI LsaApInitializePackage(ULONG, PLSA_DISPATCH_TABLE, PLSA_STRING,
    PLSA_STRING, PLSA_STRING*);
NTSTATUS NTAPI LsaApLogonUserEx2(PLSA_CLIENT_REQUEST, SECURITY_LOGON_TYPE, PVOID,
    PVOID, ULONG, PVOID*, PULONG, PLUID, PNTSTATUS,
    PLSA_TOKEN_INFORMATION_TYPE, PVOID*, PUNICODE_STRING*, PUNICODE_STRING*,
    PUNICODE_STRING*, PSECPKG_PRIMARY_CRED, PSECPKG_SUPPLEMENTAL_CRED_ARRAY*);
NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST, PVOID, PVOID, ULONG, PVOID*,
    PULONG, PNTSTATUS);
NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST, PVOID, PVOID, ULONG,
    PVOID*, PULONG, PNTSTATUS);
NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST, PVOID, PVOID, ULONG,
    PVOID*, PULONG, PNTSTATUS);
VOID NTAPI LsaApLogonTerminated(PLUID);
void SetSiLoginSspDispatch(PLSA_SECPKG_FUNCTION_TABLE);
}

namespace {
SECPKG_FUNCTION_TABLE g_table{};

NTSTATUS NTAPI SpInitialize(ULONG_PTR, PSECPKG_PARAMETERS,
    PLSA_SECPKG_FUNCTION_TABLE functions)
{
    if (!functions) return STATUS_INVALID_PARAMETER;
    SetSiLoginSspDispatch(functions);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutdown() { return STATUS_SUCCESS; }

NTSTATUS NTAPI SpGetInfo(PSecPkgInfo info)
{
    if (!info) return STATUS_INVALID_PARAMETER;
    static SEC_WCHAR name[] = L"silogin-authpak";
    static SEC_WCHAR comment[] = L"SiLogin local smart-card authentication";
    ZeroMemory(info, sizeof(*info));
    info->fCapabilities = SECPKG_FLAG_LOGON;
    info->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
    info->wRPCID = SECPKG_ID_NONE;
    info->cbMaxToken = static_cast<ULONG>(LsaAuthenticationProtocol::MaximumMessageSize);
    info->Name = name; info->Comment = comment;
    return STATUS_SUCCESS;
}
}

extern "C" NTSTATUS NTAPI SpLsaModeInitialize(ULONG lsaVersion,
    PULONG packageVersion, PSECPKG_FUNCTION_TABLE* tables, PULONG tableCount)
{
    if (!packageVersion || !tables || !tableCount ||
        lsaVersion != SECPKG_INTERFACE_VERSION) return STATUS_INVALID_PARAMETER;
    ZeroMemory(&g_table, sizeof(g_table));
    g_table.InitializePackage = LsaApInitializePackage;
    g_table.LogonUserEx2 = reinterpret_cast<PLSA_AP_LOGON_USER_EX2>(LsaApLogonUserEx2);
    g_table.Initialize = SpInitialize;
    g_table.Shutdown = SpShutdown;
    g_table.GetInfo = SpGetInfo;
    g_table.CallPackage = LsaApCallPackage;
    g_table.CallPackageUntrusted = LsaApCallPackageUntrusted;
    g_table.CallPackagePassthrough = LsaApCallPackagePassthrough;
    g_table.LogonTerminated = LsaApLogonTerminated;
    *packageVersion = SECPKG_INTERFACE_VERSION;
    *tables = &g_table;
    *tableCount = 1;
    return STATUS_SUCCESS;
}
