#include "LsaAuthenticationProtocol.h"

#include "CryptoUtilities.h"

#include <nlohmann/json.hpp>

#include <limits>
#include <stdexcept>

namespace
{
    using OrderedJson = nlohmann::ordered_json;

    constexpr const char* Protocol = "SiLogin-LSA";

    void requireMessage(const void* data, std::size_t size)
    {
        if (data == nullptr || size == 0 ||
            size > LsaAuthenticationProtocol::MaximumMessageSize)
        {
            throw std::invalid_argument("Invalid SiLogin LSA message size.");
        }
    }

    OrderedJson parseDocument(const void* data, std::size_t size)
    {
        requireMessage(data, size);
        const auto* first = static_cast<const unsigned char*>(data);
        OrderedJson document = OrderedJson::parse(first, first + size);
        if (!document.is_object() ||
            document.value("protocol", std::string{}) != Protocol ||
            document.value("version", 0U) !=
                LsaAuthenticationProtocol::CurrentVersion)
        {
            throw std::invalid_argument("Unsupported SiLogin LSA message.");
        }
        return document;
    }

    std::string requireString(const OrderedJson& value, const char* name,
        std::size_t maximum)
    {
        if (!value.contains(name) || !value.at(name).is_string())
            throw std::invalid_argument(std::string("Missing field: ") + name);
        std::string result = value.at(name).get<std::string>();
        if (result.empty() || result.size() > maximum)
            throw std::invalid_argument(std::string("Invalid field: ") + name);
        return result;
    }

    LsaLogonChallenge challengeFromJson(const OrderedJson& value)
    {
        if (!value.is_object())
            throw std::invalid_argument("Invalid challenge object.");
        LsaLogonChallenge result;
        result.id = requireString(value, "id", 128);
        result.accountSid = requireString(value, "accountSid", 184);
        result.computerName = requireString(value, "computerName", 255);
        if (!value.contains("issuedAtFileTime") ||
            !value.at("issuedAtFileTime").is_number_unsigned() ||
            !value.contains("expiresAtFileTime") ||
            !value.at("expiresAtFileTime").is_number_unsigned())
        {
            throw std::invalid_argument("Invalid challenge timestamps.");
        }
        result.issuedAtFileTime = value.at("issuedAtFileTime").get<std::uint64_t>();
        result.expiresAtFileTime = value.at("expiresAtFileTime").get<std::uint64_t>();
        if (result.expiresAtFileTime <= result.issuedAtFileTime)
            throw std::invalid_argument("Invalid challenge lifetime.");
        return result;
    }

    OrderedJson challengeToJson(const LsaLogonChallenge& challenge)
    {
        OrderedJson value;
        value["id"] = challenge.id;
        value["accountSid"] = challenge.accountSid;
        value["computerName"] = challenge.computerName;
        value["issuedAtFileTime"] = challenge.issuedAtFileTime;
        value["expiresAtFileTime"] = challenge.expiresAtFileTime;
        return value;
    }

    std::vector<unsigned char> dump(const OrderedJson& document)
    {
        const std::string text = document.dump(-1, ' ', false);
        if (text.size() > LsaAuthenticationProtocol::MaximumMessageSize)
            throw std::length_error("SiLogin LSA message is too large.");
        return { text.begin(), text.end() };
    }

    OrderedJson envelope(const char* type)
    {
        OrderedJson document;
        document["protocol"] = Protocol;
        document["version"] = LsaAuthenticationProtocol::CurrentVersion;
        document["type"] = type;
        return document;
    }
}

std::vector<unsigned char> LsaAuthenticationProtocol::challengeRequest(
    const std::string& accountSid)
{
    if (accountSid.empty() || accountSid.size() > 184)
        throw std::invalid_argument("Invalid account SID.");
    OrderedJson document = envelope("challengeRequest");
    document["accountSid"] = accountSid;
    return dump(document);
}

std::string LsaAuthenticationProtocol::parseChallengeRequest(
    const void* data, std::size_t size)
{
    const OrderedJson document = parseDocument(data, size);
    if (document.value("type", std::string{}) != "challengeRequest")
        throw std::invalid_argument("Expected a challenge request.");
    return requireString(document, "accountSid", 184);
}

std::vector<unsigned char> LsaAuthenticationProtocol::serializeChallenge(
    const LsaLogonChallenge& challenge)
{
    OrderedJson document = envelope("challenge");
    document["challenge"] = challengeToJson(challenge);
    return dump(document);
}

LsaLogonChallenge LsaAuthenticationProtocol::parseChallenge(
    const void* data, std::size_t size)
{
    const OrderedJson document = parseDocument(data, size);
    if (document.value("type", std::string{}) != "challenge" ||
        !document.contains("challenge"))
        throw std::invalid_argument("Expected a challenge.");
    return challengeFromJson(document.at("challenge"));
}

std::vector<unsigned char> LsaAuthenticationProtocol::serializeProof(
    const LsaLogonProof& proof)
{
    if (proof.certificateDer.empty() || proof.certificateDer.size() > 32768 ||
        proof.signature.empty() || proof.signature.size() > 4096)
        throw std::invalid_argument("Invalid certificate or signature size.");
    OrderedJson document = envelope("logonProof");
    document["challenge"] = challengeToJson(proof.challenge);
    document["certificateDer"] = CryptoUtilities::bytesToHex(proof.certificateDer);
    document["signature"] = CryptoUtilities::bytesToHex(proof.signature);
    return dump(document);
}

LsaLogonProof LsaAuthenticationProtocol::parseProof(
    const void* data, std::size_t size)
{
    const OrderedJson document = parseDocument(data, size);
    if (document.value("type", std::string{}) != "logonProof" ||
        !document.contains("challenge"))
        throw std::invalid_argument("Expected a logon proof.");
    LsaLogonProof proof;
    proof.challenge = challengeFromJson(document.at("challenge"));
    proof.certificateDer = CryptoUtilities::hexToBytes(
        requireString(document, "certificateDer", 65536));
    proof.signature = CryptoUtilities::hexToBytes(
        requireString(document, "signature", 8192));
    if (proof.certificateDer.empty() || proof.certificateDer.size() > 32768 ||
        proof.signature.empty() || proof.signature.size() > 4096)
        throw std::invalid_argument("Invalid certificate or signature size.");
    return proof;
}

std::vector<unsigned char> LsaAuthenticationProtocol::signingPayload(
    const LsaLogonChallenge& challenge)
{
    OrderedJson document = envelope("challengeProof");
    document["challenge"] = challengeToJson(challenge);
    return dump(document);
}
