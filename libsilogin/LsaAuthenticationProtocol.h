#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct LsaLogonChallenge
{
    std::string id;
    std::string accountSid;
    std::string computerName;
    std::uint64_t issuedAtFileTime = 0;
    std::uint64_t expiresAtFileTime = 0;
};

struct LsaLogonProof
{
    LsaLogonChallenge challenge;
    std::vector<unsigned char> certificateDer;
    std::vector<unsigned char> signature;
};

class LsaAuthenticationProtocol final
{
public:
    static constexpr unsigned int CurrentVersion = 1;
    static constexpr std::size_t MaximumMessageSize = 64 * 1024;

    static std::vector<unsigned char> challengeRequest(
        const std::string& accountSid);

    static std::string parseChallengeRequest(
        const void* data,
        std::size_t size);

    static std::vector<unsigned char> serializeChallenge(
        const LsaLogonChallenge& challenge);

    static LsaLogonChallenge parseChallenge(
        const void* data,
        std::size_t size);

    static std::vector<unsigned char> serializeProof(
        const LsaLogonProof& proof);

    static LsaLogonProof parseProof(
        const void* data,
        std::size_t size);

    // Exact bytes signed by the smart card and verified by the AP.
    static std::vector<unsigned char> signingPayload(
        const LsaLogonChallenge& challenge);
};
