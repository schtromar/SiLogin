#pragma once

#include "Certificate.h"

#include <string_view>
#include <vector>

class SmartCardSigner
{
public:
    static std::vector<unsigned char> sign(
        const Certificate& certificate,
        const std::vector<unsigned char>& payload,
        std::wstring_view smartCardPin = {},
        std::string_view readerName = {});

    static bool verify(
        const Certificate& certificate,
        const std::vector<unsigned char>& payload,
        const std::vector<unsigned char>& signature);

private:
    static std::vector<unsigned char> sha384(
        const std::vector<unsigned char>& data);
};