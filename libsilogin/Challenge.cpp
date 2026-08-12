#include "Challenge.h"

#include <windows.h>
#include <bcrypt.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

Challenge Challenge::generate()
{
    Challenge challenge;

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        challenge.randomBytes_.data(),
        static_cast<ULONG>(
            challenge.randomBytes_.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status))
    {
        std::ostringstream message;

        message
            << "BCryptGenRandom failed with status 0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(status);

        throw std::runtime_error(message.str());
    }

    return challenge;
}

const std::array<
    unsigned char,
    Challenge::RandomByteCount>&
    Challenge::randomBytes() const
{
    return randomBytes_;
}

std::vector<unsigned char> Challenge::payload() const
{
    // This prefix gives the signature a specific protocol
    // and purpose, rather than signing unexplained random data.
    static constexpr char Prefix[] =
        "SiLogin-v1|Windows-local-card-authentication|";

    std::vector<unsigned char> result;

    result.reserve(
        sizeof(Prefix) - 1 +
        randomBytes_.size());

    result.insert(
        result.end(),
        reinterpret_cast<const unsigned char*>(Prefix),
        reinterpret_cast<const unsigned char*>(Prefix) +
        sizeof(Prefix) - 1);

    result.insert(
        result.end(),
        randomBytes_.begin(),
        randomBytes_.end());

    return result;
}

std::string Challenge::randomBytesAsHex() const
{
    std::ostringstream output;

    output
        << std::hex
        << std::uppercase
        << std::setfill('0');

    for (unsigned char value : randomBytes_)
    {
        output
            << std::setw(2)
            << static_cast<unsigned int>(value);
    }

    return output.str();
}