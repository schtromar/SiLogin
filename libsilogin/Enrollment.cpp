#include "Enrollment.h"

#include "Certificate.h"
#include "WindowsAccount.h"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <iomanip>
#include <sstream>

namespace
{
    using OrderedJson = nlohmann::ordered_json;

    std::string currentUtcTime()
    {
        SYSTEMTIME time{};
        GetSystemTime(&time);

        std::ostringstream output;

        output
            << std::setfill('0')
            << std::setw(4) << time.wYear
            << '-'
            << std::setw(2) << time.wMonth
            << '-'
            << std::setw(2) << time.wDay
            << 'T'
            << std::setw(2) << time.wHour
            << ':'
            << std::setw(2) << time.wMinute
            << ':'
            << std::setw(2) << time.wSecond
            << 'Z';

        return output.str();
    }
}

Enrollment Enrollment::create(
    const WindowsAccount& account,
    const Certificate& certificate)
{
    Enrollment enrollment;

    enrollment.accountName =
        account.userName();

    enrollment.accountSid =
        account.sid();

    enrollment.certificateDisplayName =
        certificate.displayName();

    enrollment.certificateThumbprint =
        certificate.sha256Thumbprint();

    enrollment.certificateIssuer =
        certificate.issuer();

    enrollment.certificateSerialNumber =
        certificate.serialNumber();

    enrollment.enrolledAtUtc =
        currentUtcTime();

    return enrollment;
}

bool Enrollment::matches(
    const WindowsAccount& account,
    const Certificate& certificate) const
{
    return
        accountSid == account.sid() &&
        certificateThumbprint ==
        certificate.sha256Thumbprint() &&
        certificateSerialNumber ==
        certificate.serialNumber();
}

bool Enrollment::matchesSid(
    const std::string& expectedAccountSid,
    const Certificate& certificate) const
{
    return
        accountSid == expectedAccountSid &&
        certificateThumbprint ==
        certificate.sha256Thumbprint() &&
        certificateSerialNumber ==
        certificate.serialNumber();
}

void Enrollment::setRecovery(
    const std::string& recoveryIdValue,
    const std::string& payloadSha256Value)
{
    recoveryEnabled = true;

    recoveryScheme =
        "SiLogin-Recovery-v1";

    recoveryId =
        recoveryIdValue;

    recoveryPayloadSha256 =
        payloadSha256Value;
}

std::string Enrollment::canonicalPayloadJson() const
{
    OrderedJson document;

    document["format"] =
        format;

    document["version"] =
        version;

    OrderedJson account;

    account["name"] =
        accountName;

    account["sid"] =
        accountSid;

    document["account"] =
        account;

    OrderedJson certificate;

    certificate["displayName"] =
        certificateDisplayName;

    certificate["sha256Thumbprint"] =
        certificateThumbprint;

    certificate["issuer"] =
        certificateIssuer;

    certificate["serialNumber"] =
        certificateSerialNumber;

    document["certificate"] =
        certificate;

    document["enrolledAtUtc"] =
        enrolledAtUtc;

    OrderedJson recovery;

    recovery["enabled"] =
        recoveryEnabled;

    if (recoveryEnabled)
    {
        recovery["scheme"] =
            recoveryScheme;

        recovery["recoveryId"] =
            recoveryId;

        recovery["payloadSha256"] =
            recoveryPayloadSha256;
    }

    document["recovery"] =
        recovery;

    return document.dump(-1);
}

std::vector<unsigned char>
Enrollment::signingPayload() const
{
    const std::string payload =
        canonicalPayloadJson();

    return std::vector<unsigned char>(
        payload.begin(),
        payload.end());
}
