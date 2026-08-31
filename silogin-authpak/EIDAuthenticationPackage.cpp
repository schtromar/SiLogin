#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <NTSecAPI.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <NTSecPKG.h>
#include <sddl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <lmcons.h>

#include "../libsilogin/Certificate.h"
#include "../libsilogin/CryptoUtilities.h"
#include "../libsilogin/Enrollment.h"
#include "../libsilogin/IdentityStore.h"
#include "../libsilogin/LsaAuthenticationProtocol.h"
#include "../libsilogin/SmartCardSigner.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace {
constexpr char kPackageName[] = "silogin-authpak";
constexpr ULONGLONG kChallengeLifetime = 60ULL * 10000000ULL;
PLSA_DISPATCH_TABLE g_ap = nullptr;
PLSA_SECPKG_FUNCTION_TABLE g_ssp = nullptr;
std::mutex g_challengeLock;
std::map<std::string, LsaLogonChallenge> g_challenges;
std::mutex g_tokenLock;
std::map<ULONGLONG, HANDLE> g_sessionTokens;

ULONGLONG luidKey(const LUID& value)
{
    return (static_cast<ULONGLONG>(static_cast<ULONG>(value.HighPart)) << 32) |
        value.LowPart;
}

bool retainSessionToken(const LUID& logonId, HANDLE token)
{
    try
    {
        std::lock_guard<std::mutex> guard(g_tokenLock);
        return g_sessionTokens.emplace(luidKey(logonId), token).second;
    }
    catch (...)
    {
        return false;
    }
}

void releaseSessionToken(const LUID& logonId)
{
    HANDLE token = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_tokenLock);
        const auto found = g_sessionTokens.find(luidKey(logonId));
        if (found == g_sessionTokens.end()) return;
        token = found->second;
        g_sessionTokens.erase(found);
    }
    CloseHandle(token);
}

ULONGLONG nowFileTime()
{
    FILETIME value{}; GetSystemTimeAsFileTime(&value);
    return (static_cast<ULONGLONG>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

std::string randomId()
{
    std::vector<unsigned char> bytes(32);
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("BCryptGenRandom failed.");
    return CryptoUtilities::bytesToHex(bytes);
}

std::string computerName()
{
    char value[MAX_COMPUTERNAME_LENGTH + 1]{}; DWORD count = ARRAYSIZE(value);
    if (!GetComputerNameA(value, &count)) throw std::runtime_error("GetComputerName failed.");
    return std::string(value, count);
}

bool validSidText(const std::string& text)
{
    PSID sid = nullptr;
    const std::wstring wide(text.begin(), text.end());
    const BOOL ok = ConvertStringSidToSidW(wide.c_str(), &sid);
    if (sid) LocalFree(sid);
    return ok == TRUE;
}

LsaLogonChallenge issueChallenge(const std::string& sid)
{
    if (!validSidText(sid)) throw std::invalid_argument("Invalid SID.");
    LsaLogonChallenge value;
    value.id = randomId(); value.accountSid = sid; value.computerName = computerName();
    value.issuedAtFileTime = nowFileTime();
    value.expiresAtFileTime = value.issuedAtFileTime + kChallengeLifetime;
    std::lock_guard<std::mutex> guard(g_challengeLock);
    const ULONGLONG now = nowFileTime();
    for (auto i = g_challenges.begin(); i != g_challenges.end();) {
        if (i->second.expiresAtFileTime < now) i = g_challenges.erase(i); else ++i;
    }
    if (g_challenges.size() >= 256) g_challenges.erase(g_challenges.begin());
    g_challenges[value.id] = value;
    return value;
}

bool consumeChallenge(const LsaLogonChallenge& supplied)
{
    std::lock_guard<std::mutex> guard(g_challengeLock);
    const auto found = g_challenges.find(supplied.id);
    if (found == g_challenges.end()) return false;
    const LsaLogonChallenge expected = found->second;
    g_challenges.erase(found); // every attempt is one-shot, including failures
    return expected.accountSid == supplied.accountSid &&
        expected.computerName == supplied.computerName &&
        expected.issuedAtFileTime == supplied.issuedAtFileTime &&
        expected.expiresAtFileTime == supplied.expiresAtFileTime &&
        nowFileTime() <= expected.expiresAtFileTime;
}

std::optional<LsaLogonProof> validateProof(const void* data, ULONG size)
{
    try {
        LsaLogonProof proof = LsaAuthenticationProtocol::parseProof(data, size);
        if (!consumeChallenge(proof.challenge)) return std::nullopt;
        PCCERT_CONTEXT raw = CertCreateCertificateContext(X509_ASN_ENCODING,
            proof.certificateDer.data(), static_cast<DWORD>(proof.certificateDer.size()));
        if (!raw) return std::nullopt;
        Certificate certificate(raw); CertFreeCertificateContext(raw);
        if (!certificate.isPinFreeSecondFactorCertificate()) return std::nullopt;
        const IdentityStore store(proof.challenge.accountSid);
        const std::optional<Enrollment> enrollment = store.load();
        if (!enrollment || !enrollment->matchesSid(proof.challenge.accountSid, certificate))
            return std::nullopt;
        if (!SmartCardSigner::verify(certificate, enrollment->signingPayload(),
            enrollment->signature)) return std::nullopt;
        if (!SmartCardSigner::verify(certificate,
            LsaAuthenticationProtocol::signingPayload(proof.challenge), proof.signature))
            return std::nullopt;
        return proof;
    } catch (...) { return std::nullopt; }
}

PVOID allocateLsaHeap(ULONG size)
{
    if (g_ap && g_ap->AllocateLsaHeap)
        return g_ap->AllocateLsaHeap(size);
    if (g_ssp && g_ssp->AllocateLsaHeap)
        return g_ssp->AllocateLsaHeap(size);
    return nullptr;
}

void freeLsaHeap(PVOID value)
{
    if (!value) return;
    if (g_ap && g_ap->FreeLsaHeap)
        g_ap->FreeLsaHeap(value);
    else if (g_ssp && g_ssp->FreeLsaHeap)
        g_ssp->FreeLsaHeap(value);
}

NTSTATUS createLogonSession(PLUID logonId)
{
    if (g_ap && g_ap->CreateLogonSession)
        return g_ap->CreateLogonSession(logonId);
    if (g_ssp && g_ssp->CreateLogonSession)
        return g_ssp->CreateLogonSession(logonId);
    return STATUS_NOT_SUPPORTED;
}

void deleteLogonSession(PLUID logonId)
{
    if (!logonId) return;
    if (g_ap && g_ap->DeleteLogonSession)
        g_ap->DeleteLogonSession(logonId);
    else if (g_ssp && g_ssp->DeleteLogonSession)
        g_ssp->DeleteLogonSession(logonId);
}

std::vector<unsigned char> tokenData(HANDLE token,
    TOKEN_INFORMATION_CLASS informationClass)
{
    DWORD size = 0;
    GetTokenInformation(token, informationClass, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0)
        throw std::runtime_error("Could not size token information.");
    std::vector<unsigned char> value(size);
    if (!GetTokenInformation(token, informationClass, value.data(), size, &size))
        throw std::runtime_error("Could not read token information.");
    return value;
}

PVOID allocatePrivateHeap(ULONG size)
{
    if (g_ssp && g_ssp->AllocatePrivateHeap)
        return g_ssp->AllocatePrivateHeap(size);
    return nullptr;
}

void freePrivateHeap(PVOID value)
{
    if (value && g_ssp && g_ssp->FreePrivateHeap)
        g_ssp->FreePrivateHeap(value);
}

void freeTokenInformation(PLSA_TOKEN_INFORMATION_V2 value)
{
    freePrivateHeap(value);
}

std::size_t alignedSize(std::size_t value)
{
    constexpr std::size_t alignment = alignof(void*);
    return (value + alignment - 1) & ~(alignment - 1);
}

PLSA_TOKEN_INFORMATION_V2 tokenInformationFromHandle(HANDLE token)
{
    const auto userData = tokenData(token, TokenUser);
    const auto groupsData = tokenData(token, TokenGroups);
    const auto primaryData = tokenData(token, TokenPrimaryGroup);
    const auto privilegesData = tokenData(token, TokenPrivileges);
    const auto ownerData = tokenData(token, TokenOwner);
    const auto daclData = tokenData(token, TokenDefaultDacl);
    const auto statisticsData = tokenData(token, TokenStatistics);

    const auto* user = reinterpret_cast<const TOKEN_USER*>(userData.data());
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groupsData.data());
    const auto* primary = reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(primaryData.data());
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(
        privilegesData.data());
    const auto* owner = reinterpret_cast<const TOKEN_OWNER*>(ownerData.data());
    const auto* defaultDacl = reinterpret_cast<const TOKEN_DEFAULT_DACL*>(
        daclData.data());
    const auto* statistics = reinterpret_cast<const TOKEN_STATISTICS*>(
        statisticsData.data());

    std::size_t total = alignedSize(sizeof(LSA_TOKEN_INFORMATION_V2));
    total += alignedSize(GetLengthSid(user->User.Sid));
    total += alignedSize(FIELD_OFFSET(TOKEN_GROUPS, Groups) +
        groups->GroupCount * sizeof(SID_AND_ATTRIBUTES));
    for (DWORD i = 0; i < groups->GroupCount; ++i)
        total += alignedSize(GetLengthSid(groups->Groups[i].Sid));
    total += alignedSize(GetLengthSid(primary->PrimaryGroup));
    if (privileges->PrivilegeCount > 0)
        total += alignedSize(FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) +
            privileges->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES));
    if (owner->Owner)
        total += alignedSize(GetLengthSid(owner->Owner));

    DWORD aclSize = 0;
    if (defaultDacl->DefaultDacl)
    {
        ACL_SIZE_INFORMATION aclInfo{};
        if (!GetAclInformation(defaultDacl->DefaultDacl, &aclInfo,
            sizeof(aclInfo), AclSizeInformation))
            throw std::runtime_error("Could not read token DACL.");
        aclSize = aclInfo.AclBytesInUse;
        total += alignedSize(aclSize);
    }
    if (total > ULONG_MAX) throw std::length_error(
        "Token information is too large.");

    auto* base = static_cast<unsigned char*>(
        allocatePrivateHeap(static_cast<ULONG>(total)));
    auto* result = reinterpret_cast<PLSA_TOKEN_INFORMATION_V2>(base);
    if (!result) throw std::bad_alloc();
    ZeroMemory(base, total);
    unsigned char* cursor = base + alignedSize(sizeof(*result));

    auto copySid = [&cursor](PSID source) -> PSID {
        const DWORD size = GetLengthSid(source);
        PSID destination = cursor;
        if (!CopySid(size, destination, source))
            throw std::runtime_error("Could not copy token SID.");
        cursor += alignedSize(size);
        return destination;
    };

    try
    {
        result->ExpirationTime = statistics->ExpirationTime;
        result->User.User.Sid = copySid(user->User.Sid);
        result->User.User.Attributes = user->User.Attributes;

        const std::size_t groupArraySize = FIELD_OFFSET(TOKEN_GROUPS, Groups) +
            groups->GroupCount * sizeof(SID_AND_ATTRIBUTES);
        result->Groups = reinterpret_cast<PTOKEN_GROUPS>(cursor);
        cursor += alignedSize(groupArraySize);
        result->Groups->GroupCount = groups->GroupCount;
        for (DWORD i = 0; i < groups->GroupCount; ++i)
        {
            result->Groups->Groups[i].Sid = copySid(groups->Groups[i].Sid);
            result->Groups->Groups[i].Attributes = groups->Groups[i].Attributes;
        }

        result->PrimaryGroup.PrimaryGroup = copySid(primary->PrimaryGroup);

        if (privileges->PrivilegeCount > 0)
        {
            const std::size_t size = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) +
                privileges->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES);
            result->Privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(cursor);
            memcpy(result->Privileges, privileges, size);
            cursor += alignedSize(size);
        }

        result->Owner.Owner = owner->Owner ? copySid(owner->Owner) : nullptr;
        if (aclSize > 0)
        {
            result->DefaultDacl.DefaultDacl = reinterpret_cast<PACL>(cursor);
            memcpy(result->DefaultDacl.DefaultDacl, defaultDacl->DefaultDacl, aclSize);
        }
        return result;
    }
    catch (...)
    {
        freeTokenInformation(result);
        throw;
    }
}

PLSA_UNICODE_STRING lsaString(const std::wstring& value)
{
    if ((!g_ap && !g_ssp) || value.size() > USHRT_MAX / sizeof(wchar_t) - 1)
        return nullptr;
    auto result = static_cast<PLSA_UNICODE_STRING>(
        allocateLsaHeap(sizeof(LSA_UNICODE_STRING)));
    if (!result) return nullptr;
    result->MaximumLength = static_cast<USHORT>((value.size() + 1) * sizeof(wchar_t));
    result->Length = static_cast<USHORT>(value.size() * sizeof(wchar_t));
    result->Buffer = static_cast<PWSTR>(allocateLsaHeap(result->MaximumLength));
    if (!result->Buffer) { freeLsaHeap(result); return nullptr; }
    memcpy(result->Buffer, value.c_str(), result->MaximumLength);
    return result;
}

void freeLsaString(PLSA_UNICODE_STRING value)
{
    if (!value) return;
    freeLsaHeap(value->Buffer);
    freeLsaHeap(value);
}

NTSTATUS createInteractiveProfile(PLSA_CLIENT_REQUEST request,
    const std::wstring& logonServer, PVOID* profileBuffer,
    PULONG profileBufferSize)
{
    if (!request || !profileBuffer || !profileBufferSize)
        return STATUS_INVALID_PARAMETER;

    const bool useApDispatch = g_ap && g_ap->AllocateClientBuffer &&
        g_ap->CopyToClientBuffer && g_ap->FreeClientBuffer;
    if (!useApDispatch &&
        (!g_ssp || !g_ssp->AllocateClientBuffer ||
            !g_ssp->CopyToClientBuffer || !g_ssp->FreeClientBuffer))
        return STATUS_NOT_SUPPORTED;
    const auto allocateClient = useApDispatch ? g_ap->AllocateClientBuffer :
        g_ssp->AllocateClientBuffer;
    const auto copyToClient = useApDispatch ? g_ap->CopyToClientBuffer :
        g_ssp->CopyToClientBuffer;
    const auto freeClient = useApDispatch ? g_ap->FreeClientBuffer :
        g_ssp->FreeClientBuffer;

    const std::size_t serverBytes = (logonServer.size() + 1) * sizeof(wchar_t);
    const std::size_t total = sizeof(MSV1_0_INTERACTIVE_PROFILE) + serverBytes;
    if (total > ULONG_MAX || logonServer.size() > USHRT_MAX / sizeof(wchar_t) - 1)
        return STATUS_INVALID_PARAMETER;

    std::vector<unsigned char> local(total, 0);
    auto* profile = reinterpret_cast<PMSV1_0_INTERACTIVE_PROFILE>(local.data());
    profile->MessageType = MsV1_0InteractiveProfile;
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    profile->LogonTime.LowPart = now.dwLowDateTime;
    profile->LogonTime.HighPart = static_cast<LONG>(now.dwHighDateTime);
    profile->LogoffTime.QuadPart = MAXLONGLONG;
    profile->KickOffTime.QuadPart = MAXLONGLONG;
    profile->PasswordCanChange.QuadPart = 0;
    profile->PasswordMustChange.QuadPart = MAXLONGLONG;

    auto* serverText = reinterpret_cast<PWSTR>(profile + 1);
    memcpy(serverText, logonServer.c_str(), serverBytes);
    profile->LogonServer.Length = static_cast<USHORT>(
        logonServer.size() * sizeof(wchar_t));
    profile->LogonServer.MaximumLength = static_cast<USHORT>(serverBytes);

    PVOID clientBuffer = nullptr;
    NTSTATUS status = allocateClient(request,
        static_cast<ULONG>(total), &clientBuffer);
    if (status < 0) return status;

    profile->LogonServer.Buffer = reinterpret_cast<PWSTR>(
        static_cast<unsigned char*>(clientBuffer) + sizeof(*profile));
    status = copyToClient(request, static_cast<ULONG>(total),
        clientBuffer, local.data());
    if (status < 0)
    {
        freeClient(request, clientBuffer);
        return status;
    }

    *profileBuffer = clientBuffer;
    *profileBufferSize = static_cast<ULONG>(total);
    return STATUS_SUCCESS;
}

std::optional<std::wstring> accountNameForSid(const std::string& sidText)
{
    PSID sid = nullptr; const std::wstring wide(sidText.begin(), sidText.end());
    if (!ConvertStringSidToSidW(wide.c_str(), &sid)) return std::nullopt;
    wchar_t name[UNLEN + 1]{}, domain[DNLEN + 1]{};
    DWORD nc = ARRAYSIZE(name), dc = ARRAYSIZE(domain); SID_NAME_USE use{};
    const BOOL ok = LookupAccountSidW(nullptr, sid, name, &nc, domain, &dc, &use);
    wchar_t localComputer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD localComputerLength = ARRAYSIZE(localComputer);
    if (!ok || use != SidTypeUser ||
        !GetComputerNameW(localComputer, &localComputerLength))
    {
        LocalFree(sid);
        return std::nullopt;

    }

    DWORD localSidSize = 0, localDomainSize = 0;
    SID_NAME_USE localUse{};
    LookupAccountNameW(localComputer, name, nullptr, &localSidSize, nullptr,
        &localDomainSize, &localUse);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || localSidSize == 0)
    {
        LocalFree(sid);
        return std::nullopt;
    }
    std::vector<unsigned char> localSid(localSidSize);
    std::vector<wchar_t> localDomain(localDomainSize ? localDomainSize : 1);
    if (!LookupAccountNameW(localComputer, name, localSid.data(), &localSidSize,
        localDomain.data(), &localDomainSize, &localUse) ||
        localUse != SidTypeUser || !EqualSid(sid, localSid.data()))
    {
        LocalFree(sid);
        return std::nullopt;
    }
    LocalFree(sid);
    return std::wstring(localComputer) + L"\\" + name;
}

void resetOutputs(PVOID* profile, PULONG profileSize, PLUID id, PNTSTATUS sub,
    PLSA_TOKEN_INFORMATION_TYPE type, PVOID* token, PUNICODE_STRING* account,
    PUNICODE_STRING* authority, PUNICODE_STRING* machine,
    PSECPKG_PRIMARY_CRED primary, PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplemental)
{
    if (profile) *profile = nullptr; if (profileSize) *profileSize = 0;
    if (id) ZeroMemory(id, sizeof(*id)); if (sub) *sub = STATUS_LOGON_FAILURE;
    if (type) *type = LsaTokenInformationNull; if (token) *token = nullptr;
    if (account) *account = nullptr; if (authority) *authority = nullptr;
    if (machine) *machine = nullptr; if (primary) ZeroMemory(primary, sizeof(*primary));
    if (supplemental) *supplemental = nullptr;
}
}

extern "C" {
void SetSiLoginSspDispatch(PLSA_SECPKG_FUNCTION_TABLE table) { g_ssp = table; }
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

NTSTATUS NTAPI LsaApInitializePackage(ULONG, PLSA_DISPATCH_TABLE table,
    PLSA_STRING, PLSA_STRING, PLSA_STRING* packageName)
{
    if (!table || !packageName) return STATUS_INVALID_PARAMETER;
    g_ap = table;
    auto name = static_cast<PLSA_STRING>(table->AllocateLsaHeap(sizeof(LSA_STRING)));
    if (!name) return STATUS_NO_MEMORY;
    name->Buffer = static_cast<PCHAR>(table->AllocateLsaHeap(sizeof(kPackageName)));
    if (!name->Buffer) { table->FreeLsaHeap(name); return STATUS_NO_MEMORY; }
    memcpy(name->Buffer, kPackageName, sizeof(kPackageName));
    name->Length = sizeof(kPackageName) - 1; name->MaximumLength = sizeof(kPackageName);
    *packageName = name; return STATUS_SUCCESS;
}

NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST request, PVOID submit,
    PVOID, ULONG submitSize, PVOID* result, PULONG resultSize,
    PNTSTATUS protocolStatus)
{
    if (result) *result = nullptr; if (resultSize) *resultSize = 0;
    if (protocolStatus) *protocolStatus = STATUS_INVALID_PARAMETER;
    if (!request || !submit || !result || !resultSize ||
        !protocolStatus || submitSize == 0 ||
        submitSize > LsaAuthenticationProtocol::MaximumMessageSize)
        return STATUS_INVALID_PARAMETER;
    if ((!g_ap || !g_ap->AllocateClientBuffer || !g_ap->CopyToClientBuffer ||
            !g_ap->FreeClientBuffer) &&
        (!g_ssp || !g_ssp->AllocateClientBuffer || !g_ssp->CopyToClientBuffer ||
            !g_ssp->FreeClientBuffer))
        return STATUS_NOT_SUPPORTED;
    try {
        // ProtocolSubmitBuffer is the LSA-accessible copy of the submitted
        // message. ClientBufferBase is only needed to relocate pointers stored
        // inside that message; this protocol is pointer-free serialized JSON.
        const std::string sid = LsaAuthenticationProtocol::parseChallengeRequest(
            submit, submitSize);
        const auto serialized = LsaAuthenticationProtocol::serializeChallenge(issueChallenge(sid));
        PVOID client = nullptr;
        const bool useApDispatch = g_ap && g_ap->AllocateClientBuffer &&
            g_ap->CopyToClientBuffer && g_ap->FreeClientBuffer;
        const auto allocateClient = useApDispatch ? g_ap->AllocateClientBuffer :
            g_ssp->AllocateClientBuffer;
        const auto copyToClient = useApDispatch ? g_ap->CopyToClientBuffer :
            g_ssp->CopyToClientBuffer;
        const auto freeClient = useApDispatch ? g_ap->FreeClientBuffer :
            g_ssp->FreeClientBuffer;
        NTSTATUS status = allocateClient(request, static_cast<ULONG>(serialized.size()),
            &client);
        if (status < 0) { *protocolStatus = status; return STATUS_SUCCESS; }
        status = copyToClient(request, static_cast<ULONG>(serialized.size()),
            client, const_cast<unsigned char*>(serialized.data()));
        if (status < 0) {
            freeClient(request, client);
            *protocolStatus = status;
            return STATUS_SUCCESS;
        }
        *result = client; *resultSize = static_cast<ULONG>(serialized.size());
        *protocolStatus = STATUS_SUCCESS; return STATUS_SUCCESS;
    } catch (...) {
        *protocolStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
}

NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST r, PVOID b, PVOID base, ULONG n,
    PVOID* out, PULONG outSize, PNTSTATUS ps)
{ return LsaApCallPackageUntrusted(r, b, base, n, out, outSize, ps); }
NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST r, PVOID b, PVOID base,
    ULONG n, PVOID* out, PULONG outSize, PNTSTATUS ps)
{ return LsaApCallPackageUntrusted(r, b, base, n, out, outSize, ps); }

NTSTATUS NTAPI LsaApLogonUserEx2(PLSA_CLIENT_REQUEST clientRequest,
    SECURITY_LOGON_TYPE logonType,
    PVOID auth, PVOID, ULONG authSize, PVOID* profile, PULONG profileSize,
    PLUID logonId, PNTSTATUS subStatus, PLSA_TOKEN_INFORMATION_TYPE tokenType,
    PVOID* tokenInfo, PUNICODE_STRING* accountName, PUNICODE_STRING* authority,
    PUNICODE_STRING* machine, PSECPKG_PRIMARY_CRED primary,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplemental)
{
    resetOutputs(profile, profileSize, logonId, subStatus, tokenType, tokenInfo,
        accountName, authority, machine, primary, supplemental);
    if (!g_ssp || !g_ssp->GetAuthDataForUser ||
        !g_ssp->ConvertAuthDataToToken || !g_ssp->FreeLsaHeap)
        return STATUS_NOT_SUPPORTED;
    const auto proof = validateProof(auth, authSize);
    if (!proof) return STATUS_LOGON_FAILURE;
    const auto qualified = accountNameForSid(proof->challenge.accountSid);
    if (!qualified) return STATUS_NO_SUCH_USER;

    SECURITY_STRING name{};
    name.Buffer = reinterpret_cast<unsigned short*>(
        const_cast<PWSTR>(qualified->c_str()));
    name.Length = static_cast<USHORT>(qualified->size() * sizeof(wchar_t));
    name.MaximumLength = static_cast<USHORT>(name.Length + sizeof(wchar_t));
    PUCHAR authData = nullptr; ULONG authDataSize = 0;
    UNICODE_STRING flatName{};
    NTSTATUS status = g_ssp->GetAuthDataForUser(&name, SecNameSamCompatible,
        nullptr, &authData, &authDataSize, &flatName);

    // Some Windows versions do not resolve a local account through this LSA
    // callback when it is supplied as COMPUTER\user, even though the SID lookup
    // that produced that name succeeded.  Retry as a flat local SAM name.
    if (status == STATUS_NO_SUCH_USER)
    {
        const size_t slash = qualified->find(L'\\');
        if (slash != std::wstring::npos && slash + 1 < qualified->size())
        {
            const std::wstring localUser = qualified->substr(slash + 1);
            SECURITY_STRING flatUser{};
            flatUser.Buffer = reinterpret_cast<unsigned short*>(
                const_cast<PWSTR>(localUser.c_str()));
            flatUser.Length = static_cast<USHORT>(localUser.size() * sizeof(wchar_t));
            flatUser.MaximumLength = static_cast<USHORT>(
                flatUser.Length + sizeof(wchar_t));
            status = g_ssp->GetAuthDataForUser(&flatUser, SecNameFlat,
                nullptr, &authData, &authDataSize, &flatName);
        }
    }
    if (status < 0) { if (subStatus) *subStatus = status; return status; }

    const std::string machineUtf8 = computerName();
    const std::wstring localMachine(machineUtf8.begin(), machineUtf8.end());
    UNICODE_STRING authorityName{};
    authorityName.Buffer = const_cast<PWSTR>(localMachine.c_str());
    authorityName.Length = static_cast<USHORT>(localMachine.size() * sizeof(wchar_t));
    authorityName.MaximumLength = authorityName.Length;
    TOKEN_SOURCE tokenSource{};
    memcpy(tokenSource.SourceName, "SiLogin", 7);
    if (!AllocateLocallyUniqueId(&tokenSource.SourceIdentifier))
    {
        g_ssp->FreeLsaHeap(authData);
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE convertedToken = nullptr;
    UNICODE_STRING convertedAccount{};
    status = g_ssp->ConvertAuthDataToToken(authData, authDataSize,
        SecurityImpersonation, &tokenSource, logonType, &authorityName,
        &convertedToken, logonId, &convertedAccount, subStatus);
    g_ssp->FreeLsaHeap(authData);
    if (status < 0 || !convertedToken)
    {
        if (subStatus && *subStatus == STATUS_SUCCESS) *subStatus = status;
        return status < 0 ? status : STATUS_LOGON_FAILURE;
    }

    try
    {
        *tokenInfo = tokenInformationFromHandle(convertedToken);
    }
    catch (...)
    {
        CloseHandle(convertedToken);
        return STATUS_UNSUCCESSFUL;
    }
    *tokenType = LsaTokenInformationV2;
    *accountName = lsaString(*qualified);
    *authority = lsaString(localMachine);
    *machine = lsaString(localMachine);
    if (!*accountName || !*authority || !*machine) {
        freeTokenInformation(static_cast<PLSA_TOKEN_INFORMATION_V2>(*tokenInfo));
        *tokenInfo = nullptr;
        *tokenType = LsaTokenInformationNull;
        CloseHandle(convertedToken);
        return STATUS_NO_MEMORY;
    }
    // The converted token owns the logon session represented by LogonId. Keep
    // one handle alive until LSA notifies the package that the session ended;
    // closing it here makes LSA reject the otherwise valid result with
    // STATUS_NO_SUCH_LOGON_SESSION.
    if (!retainSessionToken(*logonId, convertedToken))
    {
        freeTokenInformation(static_cast<PLSA_TOKEN_INFORMATION_V2>(*tokenInfo));
        *tokenInfo = nullptr;
        *tokenType = LsaTokenInformationNull;
        CloseHandle(convertedToken);
        return STATUS_NO_MEMORY;
    }
    status = createInteractiveProfile(clientRequest, localMachine,
        profile, profileSize);
    if (status < 0)
    {
        if (subStatus) *subStatus = status;
        releaseSessionToken(*logonId);
        freeTokenInformation(static_cast<PLSA_TOKEN_INFORMATION_V2>(*tokenInfo));
        *tokenInfo = nullptr;
        *tokenType = LsaTokenInformationNull;
        freeLsaString(*accountName); *accountName = nullptr;
        freeLsaString(*authority); *authority = nullptr;
        freeLsaString(*machine); *machine = nullptr;
        return status;
    }
    if (subStatus) *subStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

VOID NTAPI LsaApLogonTerminated(PLUID logonId)
{
    if (logonId) releaseSessionToken(*logonId);
}

VOID NTAPI DllRegister() {} VOID NTAPI DllUnRegister() {}
VOID NTAPI DllEnableLogging() {} VOID NTAPI DllDisableLogging() {}
VOID NTAPI DllApplyTraceConfigW() {} VOID NTAPI CleanupLsaCredentials() {}
VOID NTAPI CleanupEIDCertificates() {}
UINT WINAPI Commit(UINT) { return ERROR_SUCCESS; }
UINT WINAPI Uninstall(UINT) { return ERROR_SUCCESS; }
}
