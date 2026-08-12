#pragma once

#include <filesystem>
#include <vector>

class RecoveryDrive
{
public:
    static constexpr const wchar_t* FileName =
        L"SiLogin-Recovery.json";

    static std::vector<std::filesystem::path>
        findRecoveryFiles();
};
