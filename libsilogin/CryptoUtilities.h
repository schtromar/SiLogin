#pragma once

#include <string>
#include <vector>

class CryptoUtilities
{
public:
    static std::vector<unsigned char> sha256(
        const std::vector<unsigned char>& data);

    static std::string bytesToHex(
        const std::vector<unsigned char>& bytes);

    static std::vector<unsigned char> hexToBytes(
        const std::string& value);

    static bool constantTimeEqual(
        const std::string& left,
        const std::string& right);
};
