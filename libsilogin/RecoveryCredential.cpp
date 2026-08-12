#include "RecoveryCredential.h"

#include "Certificate.h"
#include "CryptoUtilities.h"
#include "WindowsAccount.h"

#include <windows.h>
#include <bcrypt.h>

#include <nlohmann/json.hpp>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace
{
    using OrderedJson = nlohmann::ordered_json;

    constexpr std::uintmax_t MaximumRecoveryFileSize =
        4096;

    std::vector<unsigned char> secureRandomBytes(
        std::size_t count)
    {
        std::vector<unsigned char> bytes(count);

        const NTSTATUS status =
            BCryptGenRandom(
                nullptr,
                bytes.data(),
                static_cast<ULONG>(bytes.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (status < 0)
        {
            throw std::runtime_error(
                "BCryptGenRandom failed.");
        }

        return bytes;
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

    void requireString(
        const nlohmann::json& document,
        const char* property)
    {
        if (!document.contains(property) ||
            !document.at(property).is_string())
        {
            throw std::runtime_error(
                std::string(
                    "Invalid recovery property: ") +
                property);
        }
    }

    bool isHexString(
        const std::string& value)
    {
        for (const char character : value)
        {
            const bool decimal =
                character >= '0' &&
                character <= '9';

            const bool upper =
                character >= 'A' &&
                character <= 'F';

            const bool lower =
                character >= 'a' &&
                character <= 'f';

            if (!decimal && !upper && !lower)
            {
                return false;
            }
        }

        return true;
    }
}

RecoveryCredential RecoveryCredential::create(
    const WindowsAccount& account,
    const Certificate& certificate)
{
    RecoveryCredential credential;

    credential.recoveryId_ =
        CryptoUtilities::bytesToHex(
            secureRandomBytes(16));

    credential.secret_ =
        CryptoUtilities::bytesToHex(
            secureRandomBytes(32));

    credential.accountSid_ =
        account.sid();

    credential.certificateThumbprint_ =
        certificate.sha256Thumbprint();

    credential.createdAtUtc_ =
        currentUtcTime();

    return credential;
}

RecoveryCredential RecoveryCredential::load(
    const std::filesystem::path& path)
{
    std::error_code error;

    const std::uintmax_t fileSize =
        std::filesystem::file_size(
            path,
            error);

    if (error)
    {
        throw std::runtime_error(
            "Cannot determine the recovery-file size.");
    }

    if (fileSize == 0 ||
        fileSize > MaximumRecoveryFileSize)
    {
        throw std::runtime_error(
            "Recovery file has an invalid size.");
    }

    std::ifstream input(
        path,
        std::ios::binary);

    if (!input)
    {
        throw std::runtime_error(
            "Cannot open the recovery file.");
    }

    nlohmann::json document;

    try
    {
        input >> document;
    }
    catch (const nlohmann::json::exception&)
    {
        throw std::runtime_error(
            "Recovery file contains invalid JSON.");
    }

    if (!document.is_object())
    {
        throw std::runtime_error(
            "Recovery document must be an object.");
    }

    requireString(document, "format");
    requireString(document, "recoveryId");
    requireString(document, "secret");
    requireString(document, "accountSid");
    requireString(document, "certificateThumbprint");
    requireString(document, "createdAtUtc");

    if (!document.contains("version") ||
        !document.at("version").is_number_unsigned())
    {
        throw std::runtime_error(
            "Recovery version is missing or invalid.");
    }

    RecoveryCredential credential;

    credential.format_ =
        document.at("format").get<std::string>();

    credential.version_ =
        document.at("version").get<unsigned int>();

    credential.recoveryId_ =
        document.at("recoveryId").get<std::string>();

    credential.secret_ =
        document.at("secret").get<std::string>();

    credential.accountSid_ =
        document.at("accountSid").get<std::string>();

    credential.certificateThumbprint_ =
        document.at(
            "certificateThumbprint").get<std::string>();

    credential.createdAtUtc_ =
        document.at("createdAtUtc").get<std::string>();

    if (credential.format_ !=
        "SiLogin recovery")
    {
        throw std::runtime_error(
            "Unknown recovery-file format.");
    }

    if (credential.version_ !=
        CurrentVersion)
    {
        throw std::runtime_error(
            "Unsupported recovery-file version.");
    }

    if (credential.recoveryId_.size() != 32 ||
        !isHexString(credential.recoveryId_))
    {
        throw std::runtime_error(
            "Recovery identifier is invalid.");
    }

    if (credential.secret_.size() != 64 ||
        !isHexString(credential.secret_))
    {
        throw std::runtime_error(
            "Recovery secret is invalid.");
    }

    return credential;
}

void RecoveryCredential::save(
    const std::filesystem::path& path) const
{
    OrderedJson document;

    document["format"] =
        format_;

    document["version"] =
        version_;

    document["recoveryId"] =
        recoveryId_;

    document["secret"] =
        secret_;

    document["accountSid"] =
        accountSid_;

    document["certificateThumbprint"] =
        certificateThumbprint_;

    document["createdAtUtc"] =
        createdAtUtc_;

    std::filesystem::path temporaryPath =
        path;

    temporaryPath += L".tmp";

    {
        std::ofstream output(
            temporaryPath,
            std::ios::binary |
            std::ios::trunc);

        if (!output)
        {
            throw std::runtime_error(
                "Cannot create the recovery file.");
        }

        output
            << document.dump(4)
            << '\n';

        output.flush();

        if (!output)
        {
            throw std::runtime_error(
                "Writing the recovery file failed.");
        }
    }

    if (!MoveFileExW(
        temporaryPath.c_str(),
        path.c_str(),
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH))
    {
        std::error_code cleanupError;

        std::filesystem::remove(
            temporaryPath,
            cleanupError);

        throw std::runtime_error(
            "Cannot finalize the recovery file. "
            "Windows error: " +
            std::to_string(GetLastError()));
    }
}

std::string RecoveryCredential::canonicalPayloadJson() const
{
    OrderedJson document;

    document["scheme"] =
        "SiLogin-Recovery-v1";

    document["recoveryId"] =
        recoveryId_;

    document["secret"] =
        secret_;

    document["accountSid"] =
        accountSid_;

    document["certificateThumbprint"] =
        certificateThumbprint_;

    document["createdAtUtc"] =
        createdAtUtc_;

    return document.dump(-1);
}

std::vector<unsigned char>
RecoveryCredential::canonicalPayload() const
{
    const std::string payload =
        canonicalPayloadJson();

    return std::vector<unsigned char>(
        payload.begin(),
        payload.end());
}

const std::string&
RecoveryCredential::recoveryId() const
{
    return recoveryId_;
}

const std::string&
RecoveryCredential::accountSid() const
{
    return accountSid_;
}

const std::string&
RecoveryCredential::certificateThumbprint() const
{
    return certificateThumbprint_;
}

const std::string&
RecoveryCredential::createdAtUtc() const
{
    return createdAtUtc_;
}
