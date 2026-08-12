#pragma once
#pragma once

#include <string>
#include <vector>

class Certificate;
class WindowsAccount;

class AuthenticationRequest
{
public:
    static constexpr unsigned int CurrentVersion = 1;

    static AuthenticationRequest create(
        const WindowsAccount& account,
        const Certificate& certificate);

    static AuthenticationRequest createForSid(
        const std::string& accountSid,
        const Certificate& certificate);

    /*
     * Deterministic compact JSON used as the exact signed
     * byte sequence.
     */
    std::string canonicalJson() const;

    /*
     * Readable JSON used only for console output and
     * diagnostics.
     */
    std::string prettyJson() const;

    std::vector<unsigned char> signingPayload() const;

    const std::string& nonce() const;
    const std::string& issuedAtUtc() const;
    const std::string& computerName() const;
    const std::string& accountSid() const;
    const std::string& certificateThumbprint() const;

private:
    std::string protocol_ = "SiLogin";
    unsigned int version_ = CurrentVersion;
    std::string purpose_ = "authentication";

    std::string nonce_;
    std::string issuedAtUtc_;
    std::string computerName_;
    std::string accountSid_;
    std::string certificateThumbprint_;
};