#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <vector>

class Challenge
{
public:
    static constexpr std::size_t RandomByteCount = 32;

    static Challenge generate();

    const std::array<unsigned char, RandomByteCount>&
        randomBytes() const;

    std::vector<unsigned char> payload() const;
    std::string randomBytesAsHex() const;

private:
    std::array<unsigned char, RandomByteCount>
        randomBytes_{};
};