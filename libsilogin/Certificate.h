#pragma once

#include <windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>

class Logger;

struct CertificateInformation
{
    std::string displayName;
    std::string subject;
    std::string issuer;
    std::string serialNumber;
    std::string sha256Thumbprint;
    std::string validFrom;
    std::string validUntil;
    std::string publicKeyAlgorithm;
    DWORD publicKeyBits = 0;
    std::string providerName;
    std::string keyContainerName;
    bool currentlyValid = false;
    bool hasPrivateKeyInformation = false;
    bool smartCardBacked = false;
    bool digitalSignatureAllowed = false;
    bool clientAuthenticationEku = false;
    bool authenticationCandidate = false;
};

class Certificate
{
public:
    explicit Certificate(
        PCCERT_CONTEXT context = nullptr);

    ~Certificate();

    Certificate(
        const Certificate& other);

    Certificate& operator=(
        const Certificate& other);

    Certificate(
        Certificate&& other) noexcept;

    Certificate& operator=(
        Certificate&& other) noexcept;

    static std::vector<Certificate> enumerate(
        Logger& logger);

    static std::vector<Certificate> enumerateFromSmartCard(
        Logger& logger,
        const std::string& readerName);

    PCCERT_CONTEXT context() const;

    std::string displayName() const;
    std::string subject() const;
    std::string issuer() const;
    std::string serialNumber() const;
    std::string sha256Thumbprint() const;
    std::string validFrom() const;
    std::string validUntil() const;
    std::string publicKeyAlgorithm() const;
    DWORD publicKeyBits() const;
    std::string providerName() const;
    std::string keyContainerName() const;

    bool isCurrentlyValid() const;
    bool hasPrivateKeyInformation() const;
    bool isSmartCardBacked() const;
    bool allowsDigitalSignature() const;
    bool hasClientAuthenticationEku() const;
    bool isAuthenticationCandidate() const;
    bool isHighAssuranceAuthenticationCertificate() const;
    bool isPinFreeSecondFactorCertificate() const;

    CertificateInformation information() const;

private:
    PCCERT_CONTEXT context_ = nullptr;
};
