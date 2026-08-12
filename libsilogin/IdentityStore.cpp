#include "IdentityStore.h"

#include "CryptoUtilities.h"
#include "WindowsAccount.h"

#include <windows.h>
#include <shlobj.h>

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <system_error>

namespace
{
    using OrderedJson = nlohmann::ordered_json;

    constexpr std::uintmax_t MaximumEnrollmentFileSize =
        64 * 1024;

    OrderedJson enrollmentToJson(
        const Enrollment& enrollment)
    {
        OrderedJson document =
            OrderedJson::parse(
                enrollment.canonicalPayloadJson());

        OrderedJson signature;

        signature["scheme"] =
            enrollment.signatureScheme;

        signature["value"] =
            CryptoUtilities::bytesToHex(
                enrollment.signature);

        document["signature"] =
            signature;

        return document;
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
                    "Invalid enrollment property: ") +
                property);
        }
    }
}

namespace
{
    std::filesystem::path programDataPath()
    {
        PWSTR programData = nullptr;

        const HRESULT result =
            SHGetKnownFolderPath(
                FOLDERID_ProgramData,
                KF_FLAG_CREATE,
                nullptr,
                &programData);

        if (FAILED(result))
        {
            throw std::runtime_error(
                "Cannot locate ProgramData.");
        }

        const std::filesystem::path path(
            programData);

        CoTaskMemFree(
            programData);

        return path;
    }

    std::string validateSidForFileName(
        const std::string& accountSid)
    {
        if (accountSid.empty() ||
            accountSid.rfind("S-", 0) != 0)
        {
            throw std::invalid_argument(
                "A valid Windows account SID is required.");
        }

        for (const char character : accountSid)
        {
            const bool allowed =
                (character >= '0' && character <= '9') ||
                character == 'S' ||
                character == '-';

            if (!allowed)
            {
                throw std::invalid_argument(
                    "The Windows account SID contains "
                    "an invalid character.");
            }
        }

        return accountSid;
    }
}

IdentityStore::IdentityStore()
    : IdentityStore(
        WindowsAccount::current().sid())
{
}

IdentityStore::IdentityStore(
    std::string accountSid)
    : accountSid_(
        validateSidForFileName(
            accountSid))
{
    directoryPath_ =
        programDataPath() /
        L"SiLogin" /
        L"Enrollments";

    filePath_ =
        directoryPath_ /
        std::filesystem::path(
            accountSid_ + ".json");
}

const std::filesystem::path&
IdentityStore::filePath() const
{
    return filePath_;
}

std::optional<Enrollment>
IdentityStore::load() const
{
    std::error_code error;

    if (!std::filesystem::exists(
        filePath_,
        error))
    {
        return std::nullopt;
    }

    if (error)
    {
        throw std::runtime_error(
            "Cannot check whether enrollment exists.");
    }

    const std::uintmax_t size =
        std::filesystem::file_size(
            filePath_,
            error);

    if (error ||
        size == 0 ||
        size > MaximumEnrollmentFileSize)
    {
        throw std::runtime_error(
            "Enrollment file has an invalid size.");
    }

    std::ifstream input(
        filePath_,
        std::ios::binary);

    if (!input)
    {
        throw std::runtime_error(
            "Cannot open the enrollment file.");
    }

    nlohmann::json document;

    try
    {
        input >> document;
    }
    catch (const nlohmann::json::exception&)
    {
        throw std::runtime_error(
            "Enrollment file contains invalid JSON.");
    }

    if (!document.is_object())
    {
        throw std::runtime_error(
            "Enrollment document must be an object.");
    }

    requireString(document, "format");
    requireString(document, "enrolledAtUtc");

    if (!document.contains("version") ||
        !document.at("version").is_number_unsigned())
    {
        throw std::runtime_error(
            "Enrollment version is missing or invalid.");
    }

    if (!document.contains("account") ||
        !document.at("account").is_object())
    {
        throw std::runtime_error(
            "Enrollment account is missing or invalid.");
    }

    if (!document.contains("certificate") ||
        !document.at("certificate").is_object())
    {
        throw std::runtime_error(
            "Enrollment certificate is missing or invalid.");
    }

    if (!document.contains("recovery") ||
        !document.at("recovery").is_object())
    {
        throw std::runtime_error(
            "Enrollment recovery metadata is missing.");
    }

    if (!document.contains("signature") ||
        !document.at("signature").is_object())
    {
        throw std::runtime_error(
            "Enrollment signature is missing.");
    }

    const auto& account =
        document.at("account");

    requireString(account, "name");
    requireString(account, "sid");

    const auto& certificate =
        document.at("certificate");

    requireString(certificate, "displayName");
    requireString(certificate, "sha256Thumbprint");
    requireString(certificate, "issuer");
    requireString(certificate, "serialNumber");

    const auto& recovery =
        document.at("recovery");

    if (!recovery.contains("enabled") ||
        !recovery.at("enabled").is_boolean())
    {
        throw std::runtime_error(
            "Recovery enabled flag is missing or invalid.");
    }

    const auto& signature =
        document.at("signature");

    requireString(signature, "scheme");
    requireString(signature, "value");

    Enrollment enrollment;

    enrollment.format =
        document.at("format").get<std::string>();

    enrollment.version =
        document.at("version").get<unsigned int>();

    enrollment.accountName =
        account.at("name").get<std::string>();

    enrollment.accountSid =
        account.at("sid").get<std::string>();

    enrollment.certificateDisplayName =
        certificate.at(
            "displayName").get<std::string>();

    enrollment.certificateThumbprint =
        certificate.at(
            "sha256Thumbprint").get<std::string>();

    enrollment.certificateIssuer =
        certificate.at(
            "issuer").get<std::string>();

    enrollment.certificateSerialNumber =
        certificate.at(
            "serialNumber").get<std::string>();

    enrollment.enrolledAtUtc =
        document.at(
            "enrolledAtUtc").get<std::string>();

    enrollment.recoveryEnabled =
        recovery.at("enabled").get<bool>();

    if (enrollment.recoveryEnabled)
    {
        requireString(recovery, "scheme");
        requireString(recovery, "recoveryId");
        requireString(recovery, "payloadSha256");

        enrollment.recoveryScheme =
            recovery.at("scheme").get<std::string>();

        enrollment.recoveryId =
            recovery.at("recoveryId").get<std::string>();

        enrollment.recoveryPayloadSha256 =
            recovery.at(
                "payloadSha256").get<std::string>();
    }

    enrollment.signatureScheme =
        signature.at("scheme").get<std::string>();

    enrollment.signature =
        CryptoUtilities::hexToBytes(
            signature.at("value").get<std::string>());

    if (enrollment.format !=
        "SiLogin enrollment")
    {
        throw std::runtime_error(
            "Unknown enrollment format.");
    }

    if (enrollment.version !=
        Enrollment::CurrentVersion)
    {
        throw std::runtime_error(
            "Unsupported enrollment version. "
            "Delete the old enrollment and enroll again.");
    }

    if (enrollment.signatureScheme !=
        "SiLogin-SmartCardSigner-v1")
    {
        throw std::runtime_error(
            "Unsupported enrollment signature scheme.");
    }

    if (enrollment.signature.empty())
    {
        throw std::runtime_error(
            "Enrollment signature is empty.");
    }

    if (enrollment.recoveryEnabled &&
        enrollment.recoveryScheme !=
        "SiLogin-Recovery-v1")
    {
        throw std::runtime_error(
            "Unsupported recovery scheme.");
    }

    return enrollment;
}

void IdentityStore::save(
    const Enrollment& enrollment) const
{
    std::error_code error;

    std::filesystem::create_directories(
        directoryPath_,
        error);

    if (error)
    {
        throw std::runtime_error(
            "Cannot create the enrollment directory.");
    }

    std::filesystem::path temporaryPath =
        filePath_;

    temporaryPath += L".tmp";

    {
        std::ofstream output(
            temporaryPath,
            std::ios::binary |
            std::ios::trunc);

        if (!output)
        {
            throw std::runtime_error(
                "Cannot create the enrollment file.");
        }

        output
            << enrollmentToJson(
                enrollment).dump(4)
            << '\n';

        output.flush();

        if (!output)
        {
            throw std::runtime_error(
                "Writing the enrollment file failed.");
        }
    }

    if (!MoveFileExW(
        temporaryPath.c_str(),
        filePath_.c_str(),
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH))
    {
        std::error_code cleanupError;

        std::filesystem::remove(
            temporaryPath,
            cleanupError);

        throw std::runtime_error(
            "Cannot finalize the enrollment file. "
            "Windows error: " +
            std::to_string(GetLastError()));
    }
}
