#include "AuthenticationRequest.h"

#include "Certificate.h"
#include "Challenge.h"
#include "WindowsAccount.h"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    using OrderedJson = nlohmann::ordered_json;

    std::string wideStringToUtf8(
        const std::wstring& value)
    {
        if (value.empty())
        {
            return {};
        }

        const int requiredBytes =
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);

        if (requiredBytes <= 0)
        {
            throw std::runtime_error(
                "WideCharToMultiByte size query failed.");
        }

        std::string result(
            static_cast<std::size_t>(requiredBytes),
            '\0');

        if (WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            &result[0],
            requiredBytes,
            nullptr,
            nullptr) <= 0)
        {
            throw std::runtime_error(
                "WideCharToMultiByte failed.");
        }

        return result;
    }

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

    std::string currentComputerName()
    {
        DWORD characterCount = 0;

        /*
         * First query the required size.
         */
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            nullptr,
            &characterCount);

        if (characterCount == 0)
        {
            throw std::runtime_error(
                "GetComputerNameExW size query failed "
                "with Windows error " +
                std::to_string(GetLastError()) +
                ".");
        }

        /*
         * The returned size does not include the terminating
         * null character.
         */
        std::vector<wchar_t> buffer(
            static_cast<std::size_t>(characterCount) + 1,
            L'\0');

        DWORD actualCharacterCount =
            static_cast<DWORD>(buffer.size());

        if (!GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            buffer.data(),
            &actualCharacterCount))
        {
            throw std::runtime_error(
                "GetComputerNameExW failed with Windows error " +
                std::to_string(GetLastError()) +
                ".");
        }

        return wideStringToUtf8(
            std::wstring(
                buffer.data(),
                actualCharacterCount));
    }

    OrderedJson requestToJson(
        const std::string& protocol,
        unsigned int version,
        const std::string& purpose,
        const std::string& nonce,
        const std::string& issuedAtUtc,
        const std::string& computerName,
        const std::string& accountSid,
        const std::string& certificateThumbprint)
    {
        /*
         * Property order is part of protocol version 1.
         *
         * Changing the order requires either preserving
         * compatibility or introducing a new version.
         */
        OrderedJson document;

        document["protocol"] =
            protocol;

        document["version"] =
            version;

        document["purpose"] =
            purpose;

        document["nonce"] =
            nonce;

        document["issuedAtUtc"] =
            issuedAtUtc;

        document["computerName"] =
            computerName;

        document["accountSid"] =
            accountSid;

        document["certificateThumbprint"] =
            certificateThumbprint;

        return document;
    }
}

AuthenticationRequest AuthenticationRequest::create(
    const WindowsAccount& account,
    const Certificate& certificate)
{
    AuthenticationRequest request;

    const Challenge challenge =
        Challenge::generate();

    request.nonce_ =
        challenge.randomBytesAsHex();

    request.issuedAtUtc_ =
        currentUtcTime();

    request.computerName_ =
        currentComputerName();

    request.accountSid_ =
        account.sid();

    request.certificateThumbprint_ =
        certificate.sha256Thumbprint();

    return request;
}

AuthenticationRequest AuthenticationRequest::createForSid(
    const std::string& accountSid,
    const Certificate& certificate)
{
    if (accountSid.empty())
    {
        throw std::invalid_argument(
            "An account SID is required.");
    }

    AuthenticationRequest request;

    const Challenge challenge =
        Challenge::generate();

    request.nonce_ =
        challenge.randomBytesAsHex();

    request.issuedAtUtc_ =
        currentUtcTime();

    request.computerName_ =
        currentComputerName();

    request.accountSid_ =
        accountSid;

    request.certificateThumbprint_ =
        certificate.sha256Thumbprint();

    return request;
}

std::string AuthenticationRequest::canonicalJson() const
{
    const OrderedJson document =
        requestToJson(
            protocol_,
            version_,
            purpose_,
            nonce_,
            issuedAtUtc_,
            computerName_,
            accountSid_,
            certificateThumbprint_);

    /*
     * Compact UTF-8 JSON with no indentation.
     *
     * This exact byte sequence is signed.
     */
    return document.dump(
        -1,
        ' ',
        false);
}

std::string AuthenticationRequest::prettyJson() const
{
    const OrderedJson document =
        requestToJson(
            protocol_,
            version_,
            purpose_,
            nonce_,
            issuedAtUtc_,
            computerName_,
            accountSid_,
            certificateThumbprint_);

    return document.dump(
        4,
        ' ',
        false);
}

std::vector<unsigned char>
AuthenticationRequest::signingPayload() const
{
    const std::string json =
        canonicalJson();

    return std::vector<unsigned char>(
        json.begin(),
        json.end());
}

const std::string&
AuthenticationRequest::nonce() const
{
    return nonce_;
}

const std::string&
AuthenticationRequest::issuedAtUtc() const
{
    return issuedAtUtc_;
}

const std::string&
AuthenticationRequest::computerName() const
{
    return computerName_;
}

const std::string&
AuthenticationRequest::accountSid() const
{
    return accountSid_;
}

const std::string&
AuthenticationRequest::certificateThumbprint() const
{
    return certificateThumbprint_;
}