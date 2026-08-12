#include "SmartCardSigner.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace
{
    std::runtime_error securityStatusError(
        const char* operation,
        SECURITY_STATUS status)
    {
        std::ostringstream message;

        message
            << operation
            << " failed with status 0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(status);

        if (status == NTE_SILENT_CONTEXT)
        {
            message
                << ". The smart-card KSP/minidriver requires interactive PIN UI "
                << "for this key and would not accept a silent operation.";
        }
        else if (status == static_cast<SECURITY_STATUS>(SCARD_W_WRONG_CHV))
        {
            message << ". The smart-card PIN is incorrect.";
        }
        else if (status == static_cast<SECURITY_STATUS>(SCARD_W_CHV_BLOCKED))
        {
            message << ". The smart-card PIN is blocked.";
        }
        else if (status == static_cast<SECURITY_STATUS>(SCARD_W_CARD_NOT_AUTHENTICATED))
        {
            message
                << ". The card did not accept the supplied PIN for this key.";
        }

        return std::runtime_error(message.str());
    }

    std::runtime_error ntStatusError(
        const char* operation,
        NTSTATUS status)
    {
        std::ostringstream message;

        message
            << operation
            << " failed with status 0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(status);

        return std::runtime_error(message.str());
    }

    std::wstring utf8ToWide(
        std::string_view value)
    {
        if (value.empty())
        {
            return {};
        }

        const int requiredCharacters =
            MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0);

        if (requiredCharacters <= 0)
        {
            throw std::runtime_error(
                "Cannot convert the smart-card reader name to Unicode.");
        }

        std::wstring result(
            static_cast<std::size_t>(requiredCharacters),
            L'\0');

        if (MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value.data(),
                static_cast<int>(value.size()),
                result.data(),
                requiredCharacters) <= 0)
        {
            throw std::runtime_error(
                "Cannot convert the smart-card reader name to Unicode.");
        }

        return result;
    }


    bool certificateBlobMatches(
        PCCERT_CONTEXT certificate,
        const std::vector<unsigned char>& certificateBlob)
    {
        if (certificate == nullptr ||
            certificate->pbCertEncoded == nullptr ||
            certificate->cbCertEncoded == 0)
        {
            return false;
        }

        if (certificateBlob.size() !=
            certificate->cbCertEncoded)
        {
            return false;
        }

        return std::memcmp(
            certificateBlob.data(),
            certificate->pbCertEncoded,
            certificateBlob.size()) == 0;
    }

    bool tryReadKeyCertificate(
        NCRYPT_KEY_HANDLE keyHandle,
        std::vector<unsigned char>& certificateBlob)
    {
        DWORD certificateSize = 0;

        SECURITY_STATUS status =
            NCryptGetProperty(
                keyHandle,
                NCRYPT_CERTIFICATE_PROPERTY,
                nullptr,
                0,
                &certificateSize,
                NCRYPT_SILENT_FLAG);

        if (status != ERROR_SUCCESS ||
            certificateSize == 0)
        {
            return false;
        }

        certificateBlob.resize(
            certificateSize);

        DWORD bytesWritten = 0;

        status = NCryptGetProperty(
            keyHandle,
            NCRYPT_CERTIFICATE_PROPERTY,
            certificateBlob.data(),
            static_cast<DWORD>(
                certificateBlob.size()),
            &bytesWritten,
            NCRYPT_SILENT_FLAG);

        if (status != ERROR_SUCCESS)
        {
            certificateBlob.clear();
            return false;
        }

        certificateBlob.resize(
            bytesWritten);

        return true;
    }

    NCRYPT_KEY_HANDLE findKeyByCertificate(
        NCRYPT_PROV_HANDLE providerHandle,
        PCCERT_CONTEXT certificate)
    {
        PVOID enumerationState = nullptr;
        NCryptKeyName* keyName = nullptr;
        std::vector<std::wstring> enumeratedNames;

        try
        {
            while (true)
            {
                SECURITY_STATUS status =
                    NCryptEnumKeys(
                        providerHandle,
                        nullptr,
                        &keyName,
                        &enumerationState,
                        NCRYPT_SILENT_FLAG);

                if (status == NTE_NO_MORE_ITEMS)
                {
                    break;
                }

                if (status != ERROR_SUCCESS)
                {
                    throw securityStatusError(
                        "NCryptEnumKeys",
                        status);
                }

                if (keyName == nullptr ||
                    keyName->pszName == nullptr)
                {
                    if (keyName != nullptr)
                    {
                        NCryptFreeBuffer(
                            keyName);
                        keyName = nullptr;
                    }

                    continue;
                }

                enumeratedNames.emplace_back(
                    keyName->pszName);

                NCRYPT_KEY_HANDLE candidateKey = 0;

                status = NCryptOpenKey(
                    providerHandle,
                    &candidateKey,
                    keyName->pszName,
                    keyName->dwLegacyKeySpec,
                    NCRYPT_SILENT_FLAG);

                if (status == ERROR_SUCCESS)
                {
                    std::vector<unsigned char> candidateCertificate;

                    if (tryReadKeyCertificate(
                            candidateKey,
                            candidateCertificate) &&
                        certificateBlobMatches(
                            certificate,
                            candidateCertificate))
                    {
                        NCryptFreeBuffer(
                            keyName);
                        keyName = nullptr;

                        if (enumerationState != nullptr)
                        {
                            NCryptFreeBuffer(
                                enumerationState);
                            enumerationState = nullptr;
                        }

                        return candidateKey;
                    }

                    NCryptFreeObject(
                        candidateKey);
                }

                NCryptFreeBuffer(
                    keyName);
                keyName = nullptr;
            }

            if (enumerationState != nullptr)
            {
                NCryptFreeBuffer(
                    enumerationState);
                enumerationState = nullptr;
            }
        }
        catch (...)
        {
            if (keyName != nullptr)
            {
                NCryptFreeBuffer(
                    keyName);
            }

            if (enumerationState != nullptr)
            {
                NCryptFreeBuffer(
                    enumerationState);
            }

            throw;
        }

        std::ostringstream message;
        message
            << "The Smart Card KSP enumerated "
            << enumeratedNames.size()
            << " key(s), but none had an NCRYPT_CERTIFICATE_PROPERTY "
            << "matching the selected certificate.";

        if (!enumeratedNames.empty())
        {
            message << " Enumerated key names:";

            for (const std::wstring& name : enumeratedNames)
            {
                const int requiredBytes =
                    WideCharToMultiByte(
                        CP_UTF8,
                        0,
                        name.c_str(),
                        static_cast<int>(name.size()),
                        nullptr,
                        0,
                        nullptr,
                        nullptr);

                if (requiredBytes > 0)
                {
                    std::string utf8Name(
                        static_cast<std::size_t>(requiredBytes),
                        '\0');

                    WideCharToMultiByte(
                        CP_UTF8,
                        0,
                        name.c_str(),
                        static_cast<int>(name.size()),
                        &utf8Name[0],
                        requiredBytes,
                        nullptr,
                        nullptr);

                    message << " [" << utf8Name << "]";
                }
            }
        }

        throw std::runtime_error(
            message.str());
    }

    std::runtime_error windowsError(
        const char* operation)
    {
        std::ostringstream message;

        message
            << operation
            << " failed with Windows error 0x"
            << std::hex
            << std::uppercase
            << GetLastError();

        return std::runtime_error(message.str());
    }
}

std::vector<unsigned char> SmartCardSigner::sha384(
    const std::vector<unsigned char>& data)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA384_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        throw ntStatusError(
            "BCryptOpenAlgorithmProvider",
            status);
    }

    try
    {
        DWORD hashLength = 0;
        DWORD bytesWritten = 0;

        status = BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLength),
            sizeof(hashLength),
            &bytesWritten,
            0);

        if (!BCRYPT_SUCCESS(status))
        {
            throw ntStatusError(
                "BCryptGetProperty",
                status);
        }

        status = BCryptCreateHash(
            algorithm,
            &hashHandle,
            nullptr,
            0,
            nullptr,
            0,
            0);

        if (!BCRYPT_SUCCESS(status))
        {
            throw ntStatusError(
                "BCryptCreateHash",
                status);
        }

        if (!data.empty())
        {
            status = BCryptHashData(
                hashHandle,
                const_cast<PUCHAR>(data.data()),
                static_cast<ULONG>(data.size()),
                0);

            if (!BCRYPT_SUCCESS(status))
            {
                throw ntStatusError(
                    "BCryptHashData",
                    status);
            }
        }

        std::vector<unsigned char> hash(hashLength);

        status = BCryptFinishHash(
            hashHandle,
            hash.data(),
            static_cast<ULONG>(hash.size()),
            0);

        if (!BCRYPT_SUCCESS(status))
        {
            throw ntStatusError(
                "BCryptFinishHash",
                status);
        }

        BCryptDestroyHash(hashHandle);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return hash;
    }
    catch (...)
    {
        if (hashHandle != nullptr)
        {
            BCryptDestroyHash(hashHandle);
        }

        if (algorithm != nullptr)
        {
            BCryptCloseAlgorithmProvider(
                algorithm,
                0);
        }

        throw;
    }
}

std::vector<unsigned char> SmartCardSigner::sign(
    const Certificate& certificate,
    const std::vector<unsigned char>& payload,
    std::wstring_view smartCardPin,
    std::string_view readerName)
{
    if (certificate.context() == nullptr)
    {
        throw std::runtime_error(
            "The certificate context is null.");
    }

    std::vector<unsigned char> hash =
        sha384(payload);

    // Read the exact CNG provider/key name recorded on the certificate.
    // For CNG certificates (dwProvType == 0), Microsoft documents that
    // pwszProvName is passed to NCryptOpenStorageProvider and
    // pwszContainerName is passed to NCryptOpenKey.
    DWORD providerInfoSize = 0;

    if (!CertGetCertificateContextProperty(
            certificate.context(),
            CERT_KEY_PROV_INFO_PROP_ID,
            nullptr,
            &providerInfoSize))
    {
        throw windowsError(
            "CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) size query");
    }

    std::vector<unsigned char> providerInfoBuffer(
        providerInfoSize);

    if (!CertGetCertificateContextProperty(
            certificate.context(),
            CERT_KEY_PROV_INFO_PROP_ID,
            providerInfoBuffer.data(),
            &providerInfoSize))
    {
        throw windowsError(
            "CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID)");
    }

    auto* providerInfo =
        reinterpret_cast<CRYPT_KEY_PROV_INFO*>(
            providerInfoBuffer.data());

    if (providerInfo->dwProvType != 0)
    {
        throw std::runtime_error(
            "The selected certificate does not use a CNG key storage provider.");
    }

    if (providerInfo->pwszProvName == nullptr ||
        providerInfo->pwszProvName[0] == L'\0')
    {
        throw std::runtime_error(
            "The certificate does not contain a CNG provider name.");
    }

    if (providerInfo->pwszContainerName == nullptr ||
        providerInfo->pwszContainerName[0] == L'\0')
    {
        throw std::runtime_error(
            "The certificate does not contain a CNG key name/container.");
    }

    NCRYPT_PROV_HANDLE providerHandle = 0;
    NCRYPT_KEY_HANDLE keyHandle = 0;

    SECURITY_STATUS status =
        NCryptOpenStorageProvider(
            &providerHandle,
            providerInfo->pwszProvName,
            0);

    if (status != ERROR_SUCCESS)
    {
        throw securityStatusError(
            "NCryptOpenStorageProvider",
            status);
    }

    try
    {
        // The Microsoft Smart Card KSP can have several cards/readers and
        // GUID-named containers in its cache. Bind this provider handle to
        // the reader that PC/SC actually connected to before opening the key.
        // This avoids an interactive card-selection dialog and prevents
        // NCryptOpenKey from looking for the GUID on the wrong card.
        if (!readerName.empty())
        {
            std::wstring wideReaderName =
                utf8ToWide(readerName);

            status = NCryptSetProperty(
                providerHandle,
                NCRYPT_READER_PROPERTY,
                reinterpret_cast<PBYTE>(
                    wideReaderName.data()),
                static_cast<DWORD>(
                    (wideReaderName.size() + 1) *
                    sizeof(wchar_t)),
                NCRYPT_SILENT_FLAG);

            if (status != ERROR_SUCCESS)
            {
                throw securityStatusError(
                    "NCryptSetProperty(NCRYPT_READER_PROPERTY)",
                    status);
            }
        }

        // Do not trust CERT_KEY_PROV_INFO::pwszContainerName as the
        // name accepted by NCryptOpenKey. Some smart-card minidrivers expose
        // certificate-store metadata whose container name cannot be reopened
        // directly through the KSP. Enumerate the actual keys on the selected
        // reader and match them by the certificate blob stored on each key.
        //
        // Microsoft documents NCRYPT_CERTIFICATE_PROPERTY as the X.509
        // certificate associated with a smart-card key.
        keyHandle = findKeyByCertificate(
            providerHandle,
            certificate.context());

        try
        {
            if (!smartCardPin.empty())
            {
                std::vector<wchar_t> pinBuffer(
                    smartCardPin.begin(),
                    smartCardPin.end());

                pinBuffer.push_back(L'\0');

                status = NCryptSetProperty(
                    keyHandle,
                    NCRYPT_PIN_PROPERTY,
                    reinterpret_cast<PBYTE>(
                        pinBuffer.data()),
                    static_cast<DWORD>(
                        pinBuffer.size() * sizeof(wchar_t)),
                    NCRYPT_SILENT_FLAG);

                SecureZeroMemory(
                    pinBuffer.data(),
                    pinBuffer.size() * sizeof(wchar_t));

                if (status != ERROR_SUCCESS)
                {
                    throw securityStatusError(
                        "NCryptSetProperty(NCRYPT_PIN_PROPERTY)",
                        status);
                }
            }

            DWORD signatureLength = 0;

            status = NCryptSignHash(
                keyHandle,
                nullptr,
                hash.data(),
                static_cast<DWORD>(hash.size()),
                nullptr,
                0,
                &signatureLength,
                NCRYPT_SILENT_FLAG);

            if (status != ERROR_SUCCESS)
            {
                throw securityStatusError(
                    "NCryptSignHash size query",
                    status);
            }

            std::vector<unsigned char> signature(
                signatureLength);

            status = NCryptSignHash(
                keyHandle,
                nullptr,
                hash.data(),
                static_cast<DWORD>(hash.size()),
                signature.data(),
                static_cast<DWORD>(signature.size()),
                &signatureLength,
                NCRYPT_SILENT_FLAG);

            if (status != ERROR_SUCCESS)
            {
                throw securityStatusError(
                    "NCryptSignHash",
                    status);
            }

            signature.resize(signatureLength);

            NCryptFreeObject(keyHandle);
            keyHandle = 0;

            NCryptFreeObject(providerHandle);
            providerHandle = 0;

            return signature;
        }
        catch (...)
        {
            if (keyHandle != 0)
            {
                NCryptFreeObject(keyHandle);
                keyHandle = 0;
            }

            throw;
        }
    }
    catch (...)
    {
        if (providerHandle != 0)
        {
            NCryptFreeObject(providerHandle);
        }

        throw;
    }
}

bool SmartCardSigner::verify(
    const Certificate& certificate,
    const std::vector<unsigned char>& payload,
    const std::vector<unsigned char>& signature)
{
    if (certificate.context() == nullptr)
    {
        throw std::runtime_error(
            "The certificate context is null.");
    }

    if (signature.empty())
    {
        return false;
    }

    std::vector<unsigned char> hash =
        sha384(payload);

    BCRYPT_KEY_HANDLE publicKey = nullptr;

    if (!CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING |
        PKCS_7_ASN_ENCODING,
        &certificate
        .context()
        ->pCertInfo
        ->SubjectPublicKeyInfo,
        0,
        nullptr,
        &publicKey))
    {
        throw windowsError(
            "CryptImportPublicKeyInfoEx2");
    }

    NTSTATUS status = BCryptVerifySignature(
        publicKey,
        nullptr,
        hash.data(),
        static_cast<ULONG>(hash.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()),
        0);

    BCryptDestroyKey(publicKey);

    if (BCRYPT_SUCCESS(status))
    {
        return true;
    }

    // BCryptVerifySignature returns this value when the signature
    // is well-formed but does not match.
    constexpr NTSTATUS InvalidSignatureStatus =
        static_cast<NTSTATUS>(0xC000A000L);

    if (status == InvalidSignatureStatus)
    {
        return false;
    }

    throw ntStatusError(
        "BCryptVerifySignature",
        status);
}