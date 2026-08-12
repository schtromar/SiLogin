#include "CryptoUtilities.h"

#include <windows.h>
#include <bcrypt.h>

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

std::vector<unsigned char> CryptoUtilities::sha256(
    const std::vector<unsigned char>& data)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    try
    {
        if (BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0) < 0)
        {
            throw std::runtime_error(
                "Cannot open the SHA-256 provider.");
        }

        DWORD objectSize = 0;
        DWORD bytesWritten = 0;

        if (BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize),
            &bytesWritten,
            0) < 0)
        {
            throw std::runtime_error(
                "Cannot query the SHA-256 object size.");
        }

        DWORD digestSize = 0;

        if (BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digestSize),
            sizeof(digestSize),
            &bytesWritten,
            0) < 0)
        {
            throw std::runtime_error(
                "Cannot query the SHA-256 digest size.");
        }

        std::vector<unsigned char> hashObject(objectSize);
        std::vector<unsigned char> digest(digestSize);

        if (BCryptCreateHash(
            algorithm,
            &hash,
            hashObject.data(),
            static_cast<ULONG>(hashObject.size()),
            nullptr,
            0,
            0) < 0)
        {
            throw std::runtime_error(
                "Cannot create the SHA-256 hash.");
        }

        if (!data.empty() &&
            BCryptHashData(
                hash,
                const_cast<PUCHAR>(data.data()),
                static_cast<ULONG>(data.size()),
                0) < 0)
        {
            throw std::runtime_error(
                "Cannot hash the supplied data.");
        }

        if (BCryptFinishHash(
            hash,
            digest.data(),
            static_cast<ULONG>(digest.size()),
            0) < 0)
        {
            throw std::runtime_error(
                "Cannot finish the SHA-256 hash.");
        }

        BCryptDestroyHash(hash);
        hash = nullptr;

        BCryptCloseAlgorithmProvider(
            algorithm,
            0);
        algorithm = nullptr;

        return digest;
    }
    catch (...)
    {
        if (hash != nullptr)
        {
            BCryptDestroyHash(hash);
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

std::string CryptoUtilities::bytesToHex(
    const std::vector<unsigned char>& bytes)
{
    std::ostringstream output;

    output
        << std::hex
        << std::uppercase
        << std::setfill('0');

    for (const unsigned char byte : bytes)
    {
        output
            << std::setw(2)
            << static_cast<unsigned int>(byte);
    }

    return output.str();
}

std::vector<unsigned char> CryptoUtilities::hexToBytes(
    const std::string& value)
{
    if ((value.size() % 2) != 0)
    {
        throw std::runtime_error(
            "Hexadecimal value has an invalid length.");
    }

    auto nibble = [](char character) -> unsigned char
        {
            if (character >= '0' && character <= '9')
            {
                return static_cast<unsigned char>(
                    character - '0');
            }

            if (character >= 'A' && character <= 'F')
            {
                return static_cast<unsigned char>(
                    character - 'A' + 10);
            }

            if (character >= 'a' && character <= 'f')
            {
                return static_cast<unsigned char>(
                    character - 'a' + 10);
            }

            throw std::runtime_error(
                "Hexadecimal value contains an invalid character.");
        };

    std::vector<unsigned char> bytes;
    bytes.reserve(value.size() / 2);

    for (std::size_t index = 0;
        index < value.size();
        index += 2)
    {
        const unsigned char high =
            nibble(value[index]);

        const unsigned char low =
            nibble(value[index + 1]);

        bytes.push_back(
            static_cast<unsigned char>(
                (high << 4) | low));
    }

    return bytes;
}

bool CryptoUtilities::constantTimeEqual(
    const std::string& left,
    const std::string& right)
{
    const std::size_t maximumLength =
        left.size() > right.size()
        ? left.size()
        : right.size();

    std::size_t difference =
        left.size() ^ right.size();

    for (std::size_t index = 0;
        index < maximumLength;
        ++index)
    {
        const unsigned char leftByte =
            index < left.size()
            ? static_cast<unsigned char>(left[index])
            : 0;

        const unsigned char rightByte =
            index < right.size()
            ? static_cast<unsigned char>(right[index])
            : 0;

        difference |=
            static_cast<std::size_t>(
                leftByte ^ rightByte);
    }

    return difference == 0;
}
