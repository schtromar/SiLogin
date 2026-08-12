#pragma once

#include <string>
#include <vector>

class Certificate;
class WindowsAccount;

class Enrollment
{
public:
    static constexpr unsigned int CurrentVersion = 3;

    static Enrollment create(
        const WindowsAccount& account,
        const Certificate& certificate);

    bool matches(
        const WindowsAccount& account,
        const Certificate& certificate) const;

    bool matchesSid(
        const std::string& expectedAccountSid,
        const Certificate& certificate) const;

    void setRecovery(
        const std::string& recoveryIdValue,
        const std::string& payloadSha256Value);

    std::string canonicalPayloadJson() const;
    std::vector<unsigned char> signingPayload() const;

    std::string format =
        "SiLogin enrollment";

    unsigned int version =
        CurrentVersion;

    std::string accountName;
    std::string accountSid;

    std::string certificateDisplayName;
    std::string certificateThumbprint;
    std::string certificateIssuer;
    std::string certificateSerialNumber;

    std::string enrolledAtUtc;

    bool recoveryEnabled = false;
    std::string recoveryScheme;
    std::string recoveryId;
    std::string recoveryPayloadSha256;

    std::string signatureScheme =
        "SiLogin-SmartCardSigner-v1";

    std::vector<unsigned char> signature;
};
