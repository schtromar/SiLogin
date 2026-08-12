#include "AuthenticationWorkflow.h"

#include "AuthenticationRequest.h"
#include "Certificate.h"
#include "CryptoUtilities.h"
#include "Enrollment.h"
#include "IdentityStore.h"
#include "Logger.h"
#include "RecoveryCredential.h"
#include "RecoveryDrive.h"
#include "SmartCard.h"
#include "SmartCardSigner.h"
#include "WindowsAccount.h"

#include <windows.h>

#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace
{
    std::string bytesToHex(
        const std::vector<unsigned char>& bytes)
    {
        return CryptoUtilities::bytesToHex(
            bytes);
    }

    const Certificate* findAuthenticationCertificate(
        const std::vector<Certificate>& certificates)
    {
        for (const Certificate& certificate :
            certificates)
        {
            if (certificate.isPinFreeSecondFactorCertificate())
            {
                return &certificate;
            }
        }

        return nullptr;
    }

    std::vector<Certificate> loadSmartCardCertificates(
        Logger& logger,
        const std::string& readerName,
        DWORD timeoutMilliseconds = 5000)
    {
        const ULONGLONG startTime =
            GetTickCount64();

        while (true)
        {
            std::vector<Certificate> certificates =
                Certificate::enumerateFromSmartCard(
                    logger,
                    readerName);

            logger.debug(
                "Direct-card enumeration returned " +
                std::to_string(certificates.size()) +
                " certificate(s).");

            for (const Certificate& certificate : certificates)
            {
                const CertificateInformation information =
                    certificate.information();

                logger.debug(
                    "Direct-card certificate: " +
                    information.displayName +
                    "; valid=" +
                    std::string(information.currentlyValid ? "yes" : "no") +
                    "; digitalSignature=" +
                    std::string(information.digitalSignatureAllowed ? "yes" : "no") +
                    "; clientAuth=" +
                    std::string(information.clientAuthenticationEku ? "yes" : "no") +
                    "; pinFreeSecondFactor=" +
                    std::string(
                        certificate.isPinFreeSecondFactorCertificate()
                        ? "yes"
                        : "no") +
                    ".");

                logger.trace(
                    "Direct-card certificate subject: " +
                    information.subject +
                    "; issuer: " +
                    information.issuer +
                    ".");

                // These two fields are diagnostic only.  For a certificate
                // discovered directly through the Smart Card KSP they are
                // not prerequisites for selection, because the key was
                // already discovered by the KSP enumeration itself.
                logger.trace(
                    "Certificate-store metadata: hasPrivateKeyInformation=" +
                    std::string(
                        information.hasPrivateKeyInformation ? "yes" : "no") +
                    "; smartCardBacked=" +
                    std::string(information.smartCardBacked ? "yes" : "no") +
                    ".");
            }

            if (findAuthenticationCertificate(
                certificates) != nullptr)
            {
                return certificates;
            }

            if (GetTickCount64() - startTime >=
                timeoutMilliseconds)
            {
                throw std::runtime_error(
                    "No suitable PIN-free Slovenian eID authentication "
                    "certificate was found directly on the inserted "
                    "smart card.");
            }

            logger.trace(
                "The Smart Card KSP does not expose the expected "
                "PIN-free authentication certificate yet; retrying.");

            Sleep(250);
        }
    }
}

AuthenticationWorkflow::AuthenticationWorkflow(
    Logger& logger)
    : logger_(
        logger)
{
}

int AuthenticationWorkflow::enrollCard()
{
    logger_.message(
        "Enrollment started.");

    const WindowsAccount account =
        WindowsAccount::current();

    logger_.debug(
        "Current Windows account: " +
        account.userName() +
        " (" +
        account.sid() +
        ").");

    SmartCard card(
        logger_);
    std::vector<Certificate> certificates;

    auto prepareCard =
        [this](
            SmartCard& selectedCard,
            std::vector<Certificate>& selectedCertificates)
        -> const Certificate&
        {
            logger_.debug(
                "Initializing the smart-card system.");

            if (!selectedCard.initialize())
            {
                throw std::runtime_error(
                    "Cannot initialize the smart-card system.");
            }

            logger_.message(
                "Insert your Slovenian eID card.");

            if (!selectedCard.waitForInsertion())
            {
                throw std::runtime_error(
                    "Waiting for card insertion failed.");
            }

            logger_.message(
                "Card inserted.");

            if (!selectedCard.connect())
            {
                throw std::runtime_error(
                    "Cannot connect to the inserted card.");
            }

            const SmartCardInformation cardInformation =
                selectedCard.cardInformation();

            logger_.debug(
                "Using smart-card reader: " +
                cardInformation.readerName +
                ".");

            logger_.trace(
                "Smart-card ATR: " +
                cardInformation.atrHex +
                ".");

            logger_.debug(
                "Smart-card protocol: " +
                cardInformation.protocolName +
                ".");

            logger_.debug(
                "Enumerating certificates directly from the inserted smart card.");

            selectedCertificates =
                loadSmartCardCertificates(
                    logger_,
                    cardInformation.readerName);

            const Certificate* certificate =
                findAuthenticationCertificate(
                    selectedCertificates);

            if (certificate == nullptr)
            {
                throw std::runtime_error(
                    "No suitable authentication certificate "
                    "was found.");
            }

            logger_.message(
                "Authentication certificate selected.");

            logger_.debug(
                "Certificate: " +
                certificate->displayName() +
                "; thumbprint: " +
                certificate->sha256Thumbprint() +
                ".");

            logger_.debug(
                "Certificate provider: " +
                certificate->providerName() +
                "; key container: " +
                certificate->keyContainerName() +
                ".");

            return *certificate;
        };

    auto finishCardSession =
        [this](
            SmartCard& selectedCard)
        {
            selectedCard.disconnect();

            logger_.message(
                "Remove your eID card.");

            if (!selectedCard.waitForRemoval())
            {
                throw std::runtime_error(
                    "Waiting for card removal failed.");
            }

            logger_.message(
                "Card removed.");
        };

    const Certificate& certificate =
        prepareCard(
            card,
            certificates);

    const std::string activeReaderName =
        card.cardInformation().readerName;

    const IdentityStore store;

    const std::optional<Enrollment> existing =
        store.load();

    if (existing.has_value())
    {
        logger_.warning(
            "An existing enrollment will be replaced.");
    }

    Enrollment enrollment =
        Enrollment::create(
            account,
            certificate);

    logger_.message(
        "Signing the enrollment with the card.");

    const std::vector<unsigned char> payload =
        enrollment.signingPayload();

    enrollment.signature =
        SmartCardSigner::sign(
            certificate,
            payload,
            std::wstring_view{},
            activeReaderName);

    if (!SmartCardSigner::verify(
        certificate,
        payload,
        enrollment.signature))
    {
        throw std::runtime_error(
            "The new enrollment signature "
            "could not be verified.");
    }

    store.save(
        enrollment);

    logger_.message(
        "Enrollment saved successfully.");

    logger_.debug(
        "Enrollment path: " +
        store.filePath().string() +
        ".");

    finishCardSession(
        card);

    return 0;
}

int AuthenticationWorkflow::authenticateWithCard()
{
    const WindowsAccount account =
        WindowsAccount::current();

    return authenticateWithCardForAccount(
        account.sid());
}

int AuthenticationWorkflow::authenticateWithCardForAccount(
    const std::string& expectedAccountSid)
{
    logger_.message(
        "Card authentication started.");

    const IdentityStore store(
        expectedAccountSid);

    const std::optional<Enrollment> enrollment =
        store.load();

    if (!enrollment.has_value())
    {
        logger_.error(
            "No enrollment exists. Run "
            "'SmartCardLogin.exe enroll' first.");

        return 1;
    }

    if (enrollment->accountSid !=
        expectedAccountSid)
    {
        logger_.error(
            "The enrollment belongs to another "
            "Windows account.");

        return 1;
    }

    SmartCard card(
        logger_);
    std::vector<Certificate> certificates;

    if (!card.initialize())
    {
        throw std::runtime_error(
            "Cannot initialize the smart-card system.");
    }

    logger_.message(
        "Insert your Slovenian eID card.");

    if (!card.waitForInsertion())
    {
        throw std::runtime_error(
            "Waiting for card insertion failed.");
    }

    logger_.message(
        "Card inserted.");

    if (!card.connect())
    {
        throw std::runtime_error(
            "Cannot connect to the inserted card.");
    }

    const SmartCardInformation cardInformation =
        card.cardInformation();

    logger_.debug(
        "Using smart-card reader: " +
        cardInformation.readerName +
        ".");

    logger_.trace(
        "Smart-card ATR: " +
        cardInformation.atrHex +
        ".");

    logger_.debug(
        "Smart-card protocol: " +
        cardInformation.protocolName +
        ".");

    logger_.debug(
        "Enumerating certificates directly from the inserted smart card.");

    certificates =
        loadSmartCardCertificates(
            logger_,
            cardInformation.readerName);

    const Certificate* certificate =
        findAuthenticationCertificate(
            certificates);

    if (certificate == nullptr)
    {
        throw std::runtime_error(
            "No suitable authentication certificate "
            "was found.");
    }

    logger_.debug(
        "Selected certificate thumbprint: " +
        certificate->sha256Thumbprint() +
        ".");

    logger_.debug(
        "Selected certificate provider: " +
        certificate->providerName() +
        "; key container: " +
        certificate->keyContainerName() +
        ".");

    const std::vector<unsigned char> enrollmentPayload =
        enrollment->signingPayload();

    if (!SmartCardSigner::verify(
        *certificate,
        enrollmentPayload,
        enrollment->signature))
    {
        logger_.error(
            "The enrollment signature is invalid.");

        card.disconnect();
        return 1;
    }

    if (!enrollment->matchesSid(
        expectedAccountSid,
        *certificate))
    {
        logger_.error(
            "The inserted card does not match "
            "the enrolled identity.");

        card.disconnect();
        return 1;
    }

    const AuthenticationRequest request =
        AuthenticationRequest::createForSid(
            expectedAccountSid,
            *certificate);

    const std::vector<unsigned char> payload =
        request.signingPayload();

    logger_.debug(
        "Authentication request: " +
        request.prettyJson());

    logger_.message(
        "Signing the authentication request "
        "with the card.");

    const std::vector<unsigned char> signature =
        SmartCardSigner::sign(
            *certificate,
            payload,
            std::wstring_view{},
            cardInformation.readerName);

    logger_.debug(
        "Authentication signature size: " +
        std::to_string(
            signature.size()) +
        " bytes.");

    logger_.trace(
        "Authentication signature: " +
        bytesToHex(signature));

    if (!SmartCardSigner::verify(
        *certificate,
        payload,
        signature))
    {
        logger_.error(
            "Authentication request signature "
            "verification failed.");

        card.disconnect();
        return 1;
    }

    logger_.message(
        "Authentication successful for SID " +
        expectedAccountSid +
        ".");

    card.disconnect();

    // Do not wait for physical removal here. Credential Provider
    // serialization must return promptly after the second factor
    // succeeds. A later authentication starts a fresh card session.
    return 0;
}

int AuthenticationWorkflow::enrollRecovery(
    const std::filesystem::path& suppliedPath)
{
    logger_.message(
        "Recovery enrollment started.");

    const WindowsAccount account =
        WindowsAccount::current();

    IdentityStore store;

    const std::optional<Enrollment> existing =
        store.load();

    if (!existing.has_value())
    {
        throw std::runtime_error(
            "Card enrollment must exist before "
            "creating a recovery credential.");
    }

    if (existing->accountSid !=
        account.sid())
    {
        throw std::runtime_error(
            "The enrollment belongs to another account.");
    }

    const std::filesystem::path driveRoot =
        std::filesystem::absolute(
            suppliedPath).root_path();

    if (driveRoot.empty() ||
        !std::filesystem::exists(
            driveRoot) ||
        !std::filesystem::is_directory(
            driveRoot))
    {
        throw std::runtime_error(
            "The requested recovery drive does not exist.");
    }

    if (GetDriveTypeW(
        driveRoot.c_str()) !=
        DRIVE_REMOVABLE)
    {
        throw std::runtime_error(
            "The destination is not reported as "
            "a removable drive.");
    }

    logger_.debug(
        "Recovery destination: " +
        driveRoot.string() +
        ".");

    SmartCard card(
        logger_);
    std::vector<Certificate> certificates;

    if (!card.initialize())
    {
        throw std::runtime_error(
            "Cannot initialize the smart-card system.");
    }

    logger_.message(
        "Insert your Slovenian eID card.");

    if (!card.waitForInsertion() ||
        !card.connect())
    {
        throw std::runtime_error(
            "Cannot connect to the inserted card.");
    }

    const SmartCardInformation cardInformation =
        card.cardInformation();

    logger_.debug(
        "Using smart-card reader: " +
        cardInformation.readerName +
        ".");

    logger_.trace(
        "Smart-card ATR: " +
        cardInformation.atrHex +
        ".");

    logger_.debug(
        "Smart-card protocol: " +
        cardInformation.protocolName +
        ".");

    logger_.debug(
        "Enumerating certificates directly from the inserted smart card.");

    certificates =
        loadSmartCardCertificates(
            logger_,
            cardInformation.readerName);

    const Certificate* certificate =
        findAuthenticationCertificate(
            certificates);

    if (certificate == nullptr)
    {
        throw std::runtime_error(
            "No suitable authentication certificate "
            "was found.");
    }

    const std::vector<unsigned char> oldPayload =
        existing->signingPayload();

    if (!SmartCardSigner::verify(
        *certificate,
        oldPayload,
        existing->signature))
    {
        throw std::runtime_error(
            "The existing enrollment signature is invalid.");
    }

    if (!existing->matches(
        account,
        *certificate))
    {
        throw std::runtime_error(
            "The inserted card does not match "
            "the existing enrollment.");
    }

    const RecoveryCredential recovery =
        RecoveryCredential::create(
            account,
            *certificate);

    const std::string payloadHash =
        CryptoUtilities::bytesToHex(
            CryptoUtilities::sha256(
                recovery.canonicalPayload()));

    Enrollment updated =
        *existing;

    updated.setRecovery(
        recovery.recoveryId(),
        payloadHash);

    updated.signature.clear();

    const std::vector<unsigned char> updatedPayload =
        updated.signingPayload();

    updated.signature =
        SmartCardSigner::sign(
            *certificate,
            updatedPayload,
            std::wstring_view{},
            cardInformation.readerName);

    if (!SmartCardSigner::verify(
        *certificate,
        updatedPayload,
        updated.signature))
    {
        throw std::runtime_error(
            "The updated enrollment signature "
            "could not be verified.");
    }

    const std::filesystem::path recoveryPath =
        driveRoot /
        RecoveryDrive::FileName;

    recovery.save(
        recoveryPath);

    try
    {
        store.save(
            updated);
    }
    catch (...)
    {
        std::error_code cleanupError;

        std::filesystem::remove(
            recoveryPath,
            cleanupError);

        throw;
    }

    logger_.message(
        "Recovery enrollment completed.");

    logger_.message(
        "Store the recovery drive securely and offline.");

    logger_.debug(
        "Recovery file path: " +
        recoveryPath.string() +
        ".");

    card.disconnect();

    logger_.message(
        "Remove your eID card.");

    if (!card.waitForRemoval())
    {
        throw std::runtime_error(
            "Waiting for card removal failed.");
    }

    logger_.message(
        "Card removed.");

    return 0;
}

int AuthenticationWorkflow::authenticateWithRecovery()
{
    const WindowsAccount account =
        WindowsAccount::current();

    return authenticateWithRecoveryForAccount(
        account.sid());
}

int AuthenticationWorkflow::authenticateWithRecoveryForAccount(
    const std::string& expectedAccountSid)
{
    logger_.message(
        "Recovery authentication started.");

    const IdentityStore store(
        expectedAccountSid);

    const std::optional<Enrollment> enrollment =
        store.load();

    if (!enrollment.has_value())
    {
        logger_.error(
            "No enrollment exists.");

        return 1;
    }

    if (enrollment->accountSid !=
        expectedAccountSid)
    {
        logger_.error(
            "The enrollment belongs to another "
            "Windows account.");

        return 1;
    }

    if (!enrollment->recoveryEnabled)
    {
        logger_.error(
            "Recovery authentication is not enabled.");

        return 1;
    }

    const auto recoveryFiles =
        RecoveryDrive::findRecoveryFiles();

    logger_.debug(
        "Found " +
        std::to_string(
            recoveryFiles.size()) +
        " recovery-file candidate(s).");

    if (recoveryFiles.empty())
    {
        logger_.error(
            "No recovery file was found on a "
            "removable drive.");

        return 1;
    }

    for (const auto& path :
        recoveryFiles)
    {
        logger_.trace(
            "Checking recovery file: " +
            path.string() +
            ".");

        try
        {
            const RecoveryCredential recovery =
                RecoveryCredential::load(
                    path);

            if (recovery.accountSid() !=
                expectedAccountSid)
            {
                logger_.debug(
                    "Recovery candidate belongs to "
                    "another Windows account.");

                continue;
            }

            if (recovery.recoveryId() !=
                enrollment->recoveryId)
            {
                logger_.debug(
                    "Recovery identifier does not match.");

                continue;
            }

            if (recovery.certificateThumbprint() !=
                enrollment->certificateThumbprint)
            {
                logger_.debug(
                    "Recovery certificate identity "
                    "does not match.");

                continue;
            }

            const std::string candidateHash =
                CryptoUtilities::bytesToHex(
                    CryptoUtilities::sha256(
                        recovery.canonicalPayload()));

            if (!CryptoUtilities::constantTimeEqual(
                candidateHash,
                enrollment->recoveryPayloadSha256))
            {
                logger_.warning(
                    "Recovery credential hash "
                    "verification failed.");

                continue;
            }

            logger_.message(
                "Recovery authentication successful "
                "for SID " +
                expectedAccountSid +
                ".");

            logger_.debug(
                "Accepted recovery file: " +
                path.string() +
                ".");

            logger_.warning(
                "Rotate the recovery credential "
                "after use.");

            return 0;
        }
        catch (const std::exception& exception)
        {
            logger_.warning(
                "Ignoring an invalid recovery file: " +
                std::string(
                    exception.what()));
        }
    }

    logger_.error(
        "No valid enrolled recovery credential "
        "was found.");

    return 1;
}
