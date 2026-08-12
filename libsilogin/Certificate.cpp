#include "Certificate.h"

#include "Logger.h"

#include <bcrypt.h>
#include <ncrypt.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace
{
    constexpr const char* PersonalStoreName = "MY";

    std::string wideStringToUtf8(
        const std::wstring& value)
    {
        if (value.empty())
        {
            return {};
        }

        int requiredBytes = WideCharToMultiByte(
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
            return {};
        }

        std::string result(
            static_cast<std::size_t>(requiredBytes),
            '\0');

        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            result.data(),
            requiredBytes,
            nullptr,
            nullptr);

        return result;
    }

    std::string bytesToHex(
        const BYTE* data,
        DWORD length,
        bool reverse = false)
    {
        if (data == nullptr || length == 0)
        {
            return {};
        }

        std::ostringstream output;

        output
            << std::hex
            << std::uppercase
            << std::setfill('0');

        if (reverse)
        {
            for (DWORD index = length; index > 0; --index)
            {
                output
                    << std::setw(2)
                    << static_cast<unsigned int>(
                        data[index - 1]);
            }
        }
        else
        {
            for (DWORD index = 0; index < length; ++index)
            {
                output
                    << std::setw(2)
                    << static_cast<unsigned int>(
                        data[index]);
            }
        }

        return output.str();
    }

    std::string certificateNameToString(
        CERT_NAME_BLOB name)
    {
        DWORD requiredCharacters = CertNameToStrW(
            X509_ASN_ENCODING |
            PKCS_7_ASN_ENCODING,
            &name,
            CERT_X500_NAME_STR,
            nullptr,
            0);

        if (requiredCharacters == 0)
        {
            return {};
        }

        std::vector<wchar_t> buffer(requiredCharacters);

        if (CertNameToStrW(
            X509_ASN_ENCODING |
            PKCS_7_ASN_ENCODING,
            &name,
            CERT_X500_NAME_STR,
            buffer.data(),
            requiredCharacters) == 0)
        {
            return {};
        }

        return wideStringToUtf8(buffer.data());
    }

    std::string certificateDisplayName(
        PCCERT_CONTEXT certificate)
    {
        DWORD requiredCharacters =
            CertGetNameStringW(
                certificate,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                nullptr,
                nullptr,
                0);

        if (requiredCharacters == 0)
        {
            return {};
        }

        std::vector<wchar_t> buffer(requiredCharacters);

        if (CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            buffer.data(),
            requiredCharacters) == 0)
        {
            return {};
        }

        return wideStringToUtf8(buffer.data());
    }

    std::string fileTimeToString(
        const FILETIME& fileTime)
    {
        SYSTEMTIME systemTime{};

        if (!FileTimeToSystemTime(
            &fileTime,
            &systemTime))
        {
            return {};
        }

        std::ostringstream output;

        output
            << std::setfill('0')
            << std::setw(4)
            << systemTime.wYear
            << '-'
            << std::setw(2)
            << systemTime.wMonth
            << '-'
            << std::setw(2)
            << systemTime.wDay
            << ' '
            << std::setw(2)
            << systemTime.wHour
            << ':'
            << std::setw(2)
            << systemTime.wMinute
            << ':'
            << std::setw(2)
            << systemTime.wSecond
            << " UTC";

        return output.str();
    }

    bool getProviderInfo(
        PCCERT_CONTEXT certificate,
        std::wstring& providerName,
        std::wstring& containerName)
    {
        DWORD bufferSize = 0;

        if (!CertGetCertificateContextProperty(
            certificate,
            CERT_KEY_PROV_INFO_PROP_ID,
            nullptr,
            &bufferSize))
        {
            return false;
        }

        std::vector<BYTE> buffer(bufferSize);

        if (!CertGetCertificateContextProperty(
            certificate,
            CERT_KEY_PROV_INFO_PROP_ID,
            buffer.data(),
            &bufferSize))
        {
            return false;
        }

        auto* providerInfo =
            reinterpret_cast<CRYPT_KEY_PROV_INFO*>(
                buffer.data());

        if (providerInfo->pwszProvName != nullptr)
        {
            providerName = providerInfo->pwszProvName;
        }

        if (providerInfo->pwszContainerName != nullptr)
        {
            containerName =
                providerInfo->pwszContainerName;
        }

        return true;
    }

    bool hasEnhancedKeyUsage(
        PCCERT_CONTEXT certificate,
        const char* requiredOid)
    {
        DWORD bufferSize = 0;

        if (!CertGetEnhancedKeyUsage(
            certificate,
            0,
            nullptr,
            &bufferSize))
        {
            return false;
        }

        std::vector<BYTE> buffer(bufferSize);

        auto* enhancedKeyUsage =
            reinterpret_cast<PCERT_ENHKEY_USAGE>(
                buffer.data());

        if (!CertGetEnhancedKeyUsage(
            certificate,
            0,
            enhancedKeyUsage,
            &bufferSize))
        {
            return false;
        }

        for (DWORD index = 0;
            index < enhancedKeyUsage->cUsageIdentifier;
            ++index)
        {
            const char* oid =
                enhancedKeyUsage->rgpszUsageIdentifier[index];

            if (oid != nullptr &&
                std::strcmp(oid, requiredOid) == 0)
            {
                return true;
            }
        }

        return false;
    }

    std::string algorithmNameFromOid(
        const char* oid)
    {
        if (oid == nullptr)
        {
            return "Unknown";
        }

        if (std::strcmp(
            oid,
            szOID_ECC_PUBLIC_KEY) == 0)
        {
            return "Elliptic Curve";
        }

        if (std::strcmp(
            oid,
            szOID_RSA_RSA) == 0)
        {
            return "RSA";
        }

        if (std::strcmp(
            oid,
            szOID_X957_DSA) == 0)
        {
            return "DSA";
        }

        return oid;
    }

    std::wstring utf8ToWide(
        const std::string& value)
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
            return {};
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
            return {};
        }

        return result;
    }

    std::string securityStatusText(
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

        return message.str();
    }

    bool attachSmartCardProviderInfo(
        PCCERT_CONTEXT certificate,
        const wchar_t* keyName)
    {
        if (certificate == nullptr ||
            keyName == nullptr ||
            keyName[0] == L'\0')
        {
            return false;
        }

        CRYPT_KEY_PROV_INFO providerInfo{};
        providerInfo.pwszContainerName =
            const_cast<LPWSTR>(keyName);
        providerInfo.pwszProvName =
            const_cast<LPWSTR>(
                MS_SMART_CARD_KEY_STORAGE_PROVIDER);
        providerInfo.dwProvType = 0;
        providerInfo.dwFlags = 0;
        providerInfo.cProvParam = 0;
        providerInfo.rgProvParam = nullptr;
        providerInfo.dwKeySpec = 0;

        return CertSetCertificateContextProperty(
            certificate,
            CERT_KEY_PROV_INFO_PROP_ID,
            0,
            &providerInfo) != FALSE;
    }
}

Certificate::Certificate(
    PCCERT_CONTEXT context)
{
    if (context != nullptr)
    {
        context_ =
            CertDuplicateCertificateContext(context);
    }
}

Certificate::~Certificate()
{
    if (context_ != nullptr)
    {
        CertFreeCertificateContext(context_);
        context_ = nullptr;
    }
}

Certificate::Certificate(
    const Certificate& other)
{
    if (other.context_ != nullptr)
    {
        context_ =
            CertDuplicateCertificateContext(
                other.context_);
    }
}

Certificate& Certificate::operator=(
    const Certificate& other)
{
    if (this == &other)
    {
        return *this;
    }

    PCCERT_CONTEXT newContext = nullptr;

    if (other.context_ != nullptr)
    {
        newContext =
            CertDuplicateCertificateContext(
                other.context_);
    }

    if (context_ != nullptr)
    {
        CertFreeCertificateContext(context_);
    }

    context_ = newContext;

    return *this;
}

Certificate::Certificate(
    Certificate&& other) noexcept
    : context_(other.context_)
{
    other.context_ = nullptr;
}

Certificate& Certificate::operator=(
    Certificate&& other) noexcept
{
    if (this == &other)
    {
        return *this;
    }

    if (context_ != nullptr)
    {
        CertFreeCertificateContext(context_);
    }

    context_ = other.context_;
    other.context_ = nullptr;

    return *this;
}

std::vector<Certificate> Certificate::enumerate(
    Logger& logger)
{
    std::vector<Certificate> certificates;

    HCERTSTORE store = CertOpenSystemStoreA(
        0,
        PersonalStoreName);

    if (store == nullptr)
    {
        std::ostringstream message;

        message
            << "CertOpenSystemStoreA failed with Windows error 0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(GetLastError())
            << '.';

        logger.error(
            message.str());

        return certificates;
    }

    PCCERT_CONTEXT current = nullptr;

    while ((current =
        CertEnumCertificatesInStore(
            store,
            current)) != nullptr)
    {
        certificates.emplace_back(current);
    }

    if (!CertCloseStore(
        store,
        0))
    {
        std::ostringstream message;

        message
            << "CertCloseStore failed with Windows error 0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(GetLastError())
            << '.';

        logger.warning(
            message.str());
    }

    logger.trace(
        "Enumerated " +
        std::to_string(certificates.size()) +
        " certificate(s) from the current user's personal store.");

    return certificates;
}


std::vector<Certificate> Certificate::enumerateFromSmartCard(
    Logger& logger,
    const std::string& readerName)
{
    std::vector<Certificate> certificates;

    if (readerName.empty())
    {
        logger.error(
            "Cannot enumerate smart-card certificates without a reader name.");
        return certificates;
    }

    const std::wstring wideReaderName =
        utf8ToWide(readerName);

    if (wideReaderName.empty())
    {
        logger.error(
            "Cannot convert the smart-card reader name to Unicode.");
        return certificates;
    }

    NCRYPT_PROV_HANDLE providerHandle = 0;

    SECURITY_STATUS status =
        NCryptOpenStorageProvider(
            &providerHandle,
            MS_SMART_CARD_KEY_STORAGE_PROVIDER,
            0);

    if (status != ERROR_SUCCESS)
    {
        logger.error(
            securityStatusText(
                "NCryptOpenStorageProvider",
                status));
        return certificates;
    }

    PVOID enumerationState = nullptr;
    NCryptKeyName* keyName = nullptr;

    try
    {
        status = NCryptSetProperty(
            providerHandle,
            NCRYPT_READER_PROPERTY,
            reinterpret_cast<PBYTE>(
                const_cast<wchar_t*>(
                    wideReaderName.c_str())),
            static_cast<DWORD>(
                (wideReaderName.size() + 1) *
                sizeof(wchar_t)),
            NCRYPT_SILENT_FLAG);

        if (status != ERROR_SUCCESS)
        {
            throw std::runtime_error(
                securityStatusText(
                    "NCryptSetProperty(NCRYPT_READER_PROPERTY)",
                    status));
        }

        while (true)
        {
            status = NCryptEnumKeys(
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
                throw std::runtime_error(
                    securityStatusText(
                        "NCryptEnumKeys",
                        status));
            }

            if (keyName == nullptr ||
                keyName->pszName == nullptr)
            {
                if (keyName != nullptr)
                {
                    NCryptFreeBuffer(keyName);
                    keyName = nullptr;
                }

                continue;
            }

            const std::wstring currentKeyName =
                keyName->pszName;

            logger.trace(
                "Smart Card KSP key: " +
                wideStringToUtf8(currentKeyName) +
                ".");

            NCRYPT_KEY_HANDLE keyHandle = 0;

            status = NCryptOpenKey(
                providerHandle,
                &keyHandle,
                keyName->pszName,
                keyName->dwLegacyKeySpec,
                NCRYPT_SILENT_FLAG);

            if (status == ERROR_SUCCESS)
            {
                DWORD certificateSize = 0;
                DWORD bytesWritten = 0;

                status = NCryptGetProperty(
                    keyHandle,
                    NCRYPT_CERTIFICATE_PROPERTY,
                    nullptr,
                    0,
                    &certificateSize,
                    NCRYPT_SILENT_FLAG);

                if (status == ERROR_SUCCESS &&
                    certificateSize > 0)
                {
                    std::vector<BYTE> certificateBlob(
                        certificateSize);

                    status = NCryptGetProperty(
                        keyHandle,
                        NCRYPT_CERTIFICATE_PROPERTY,
                        certificateBlob.data(),
                        static_cast<DWORD>(
                            certificateBlob.size()),
                        &bytesWritten,
                        NCRYPT_SILENT_FLAG);

                    if (status == ERROR_SUCCESS &&
                        bytesWritten > 0)
                    {
                        PCCERT_CONTEXT context =
                            CertCreateCertificateContext(
                                X509_ASN_ENCODING |
                                PKCS_7_ASN_ENCODING,
                                certificateBlob.data(),
                                bytesWritten);

                        if (context != nullptr)
                        {
                            if (attachSmartCardProviderInfo(
                                context,
                                currentKeyName.c_str()))
                            {
                                certificates.emplace_back(
                                    context);
                            }
                            else
                            {
                                logger.warning(
                                    "Could not attach Smart Card KSP metadata "
                                    "to an enumerated certificate.");
                            }

                            CertFreeCertificateContext(
                                context);
                        }
                        else
                        {
                            logger.warning(
                                "The Smart Card KSP returned a certificate "
                                "blob that Windows could not parse.");
                        }
                    }
                }
                else if (status != ERROR_SUCCESS)
                {
                    logger.trace(
                        securityStatusText(
                            "NCryptGetProperty(NCRYPT_CERTIFICATE_PROPERTY)",
                            status));
                }

                NCryptFreeObject(
                    keyHandle);
            }
            else
            {
                logger.trace(
                    securityStatusText(
                        "NCryptOpenKey while enumerating certificates",
                        status));
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

        NCryptFreeObject(
            providerHandle);
        providerHandle = 0;
    }
    catch (const std::exception& exception)
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

        if (providerHandle != 0)
        {
            NCryptFreeObject(
                providerHandle);
        }

        logger.error(
            std::string(
                "Direct smart-card certificate enumeration failed: ") +
            exception.what());

        return {};
    }

    logger.debug(
        "Enumerated " +
        std::to_string(certificates.size()) +
        " certificate(s) directly from reader " +
        readerName +
        ".");

    for (const Certificate& certificate : certificates)
    {
        logger.trace(
            "Card certificate: " +
            certificate.displayName() +
            "; thumbprint: " +
            certificate.sha256Thumbprint() +
            "; key: " +
            certificate.keyContainerName() +
            ".");
    }

    return certificates;
}

PCCERT_CONTEXT Certificate::context() const
{
    return context_;
}

std::string Certificate::displayName() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    return certificateDisplayName(context_);
}

std::string Certificate::subject() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    return certificateNameToString(
        context_->pCertInfo->Subject);
}

std::string Certificate::issuer() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    return certificateNameToString(
        context_->pCertInfo->Issuer);
}

std::string Certificate::serialNumber() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    // X.509 INTEGER values are stored little-endian
    // in the Windows CRYPT_INTEGER_BLOB structure.
    return bytesToHex(
        context_->pCertInfo->SerialNumber.pbData,
        context_->pCertInfo->SerialNumber.cbData,
        true);
}

std::string Certificate::sha256Thumbprint() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    DWORD hashLength = 0;

    if (!CertGetCertificateContextProperty(
        context_,
        CERT_SHA256_HASH_PROP_ID,
        nullptr,
        &hashLength))
    {
        return {};
    }

    std::vector<BYTE> hash(hashLength);

    if (!CertGetCertificateContextProperty(
        context_,
        CERT_SHA256_HASH_PROP_ID,
        hash.data(),
        &hashLength))
    {
        return {};
    }

    return bytesToHex(
        hash.data(),
        hashLength);
}

std::string Certificate::validFrom() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    return fileTimeToString(
        context_->pCertInfo->NotBefore);
}

std::string Certificate::validUntil() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    return fileTimeToString(
        context_->pCertInfo->NotAfter);
}

std::string Certificate::publicKeyAlgorithm() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    return algorithmNameFromOid(
        context_
        ->pCertInfo
        ->SubjectPublicKeyInfo
        .Algorithm
        .pszObjId);
}

DWORD Certificate::publicKeyBits() const
{
    if (context_ == nullptr)
    {
        return 0;
    }

    return CertGetPublicKeyLength(
        X509_ASN_ENCODING |
        PKCS_7_ASN_ENCODING,
        &context_
        ->pCertInfo
        ->SubjectPublicKeyInfo);
}

std::string Certificate::providerName() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    std::wstring provider;
    std::wstring container;

    if (!getProviderInfo(
        context_,
        provider,
        container))
    {
        return {};
    }

    return wideStringToUtf8(provider);
}

std::string Certificate::keyContainerName() const
{
    if (context_ == nullptr)
    {
        return {};
    }

    std::wstring provider;
    std::wstring container;

    if (!getProviderInfo(
        context_,
        provider,
        container))
    {
        return {};
    }

    return wideStringToUtf8(container);
}

bool Certificate::isCurrentlyValid() const
{
    if (context_ == nullptr)
    {
        return false;
    }

    return CertVerifyTimeValidity(
        nullptr,
        context_->pCertInfo) == 0;
}

bool Certificate::hasPrivateKeyInformation() const
{
    if (context_ == nullptr)
    {
        return false;
    }

    DWORD size = 0;

    return CertGetCertificateContextProperty(
        context_,
        CERT_KEY_PROV_INFO_PROP_ID,
        nullptr,
        &size) != FALSE;
}

bool Certificate::isSmartCardBacked() const
{
    if (context_ == nullptr)
    {
        return false;
    }

    std::wstring provider;
    std::wstring container;

    if (!getProviderInfo(
        context_,
        provider,
        container))
    {
        return false;
    }

    return _wcsicmp(
        provider.c_str(),
        MS_SMART_CARD_KEY_STORAGE_PROVIDER) == 0;
}

bool Certificate::allowsDigitalSignature() const
{
    if (context_ == nullptr)
    {
        return false;
    }

    BYTE keyUsage[2]{};

    if (!CertGetIntendedKeyUsage(
        X509_ASN_ENCODING |
        PKCS_7_ASN_ENCODING,
        context_->pCertInfo,
        keyUsage,
        sizeof(keyUsage)))
    {
        // A missing Key Usage extension means that the
        // certificate is not restricted by that extension.
        return GetLastError() == CRYPT_E_NOT_FOUND;
    }

    return (
        keyUsage[0] &
        CERT_DIGITAL_SIGNATURE_KEY_USAGE) != 0;
}

bool Certificate::hasClientAuthenticationEku() const
{
    if (context_ == nullptr)
    {
        return false;
    }

    return hasEnhancedKeyUsage(
        context_,
        szOID_PKIX_KP_CLIENT_AUTH);
}

bool Certificate::isAuthenticationCandidate() const
{
    return isCurrentlyValid() &&
        hasPrivateKeyInformation() &&
        isSmartCardBacked() &&
        allowsDigitalSignature() &&
        hasClientAuthenticationEku();
}

bool Certificate::isHighAssuranceAuthenticationCertificate() const
{
    // IMPORTANT:
    // This predicate intentionally examines only information contained
    // in the X.509 certificate itself.  Certificates returned by
    // enumerateFromSmartCard() are created from NCRYPT_CERTIFICATE_PROPERTY
    // after the private key has already been discovered through the Smart
    // Card KSP.  Such certificate contexts do not need (and may not carry)
    // the CurrentUser\\MY certificate-store metadata normally used by
    // hasPrivateKeyInformation() / isSmartCardBacked().
    if (!isCurrentlyValid() ||
        !allowsDigitalSignature() ||
        !hasClientAuthenticationEku())
    {
        return false;
    }

    const std::string name = displayName();
    const std::string subjectName = subject();
    const std::string issuerName = issuer();

    // Slovenian eID high-assurance authentication certificate.
    // Explicitly reject the qualified-signature certificate, which may
    // also advertise the Client Authentication EKU.
    const bool loginCertificate =
        name.find("prijava") != std::string::npos ||
        subjectName.find("eOI - prijava") != std::string::npos;

    const bool signingCertificate =
        name.find("podpis") != std::string::npos ||
        subjectName.find("eOI - podpis") != std::string::npos;

    const bool highAssurance =
        subjectName.find("Visoka raven zanesljivosti") != std::string::npos ||
        issuerName.find("SI-TRUST eID Visoka raven") != std::string::npos;

    return loginCertificate &&
        !signingCertificate &&
        highAssurance;
}


bool Certificate::isPinFreeSecondFactorCertificate() const
{
    // This predicate intentionally uses only X.509 contents. The certificate
    // is already known to come from a key enumerated by the Microsoft Smart
    // Card KSP, so CurrentUser\\MY store metadata is neither required nor
    // desirable here.
    if (!isCurrentlyValid() ||
        !allowsDigitalSignature() ||
        !hasClientAuthenticationEku())
    {
        return false;
    }

    const std::string name = displayName();
    const std::string subjectName = subject();
    const std::string issuerName = issuer();

    const bool pinFreeLogin =
        name.find("prijava brez PIN-a") != std::string::npos ||
        subjectName.find("prijava brez PIN-a") != std::string::npos ||
        subjectName.find("Nizka raven zanesljivosti") != std::string::npos ||
        issuerName.find("SI-TRUST eID Nizka raven") != std::string::npos;

    const bool wrongProfile =
        subjectName.find("Visoka raven zanesljivosti") != std::string::npos ||
        issuerName.find("SI-TRUST eID Visoka raven") != std::string::npos ||
        name.find("podpis") != std::string::npos ||
        subjectName.find("eOI - podpis") != std::string::npos;

    return pinFreeLogin && !wrongProfile;
}

CertificateInformation Certificate::information() const
{
    CertificateInformation result;

    result.displayName = displayName();
    result.subject = subject();
    result.issuer = issuer();
    result.serialNumber = serialNumber();
    result.sha256Thumbprint = sha256Thumbprint();
    result.validFrom = validFrom();
    result.validUntil = validUntil();
    result.publicKeyAlgorithm = publicKeyAlgorithm();
    result.publicKeyBits = publicKeyBits();
    result.providerName = providerName();
    result.keyContainerName = keyContainerName();
    result.currentlyValid = isCurrentlyValid();
    result.hasPrivateKeyInformation =
        hasPrivateKeyInformation();
    result.smartCardBacked = isSmartCardBacked();
    result.digitalSignatureAllowed =
        allowsDigitalSignature();
    result.clientAuthenticationEku =
        hasClientAuthenticationEku();
    result.authenticationCandidate =
        isAuthenticationCandidate();

    return result;
}
