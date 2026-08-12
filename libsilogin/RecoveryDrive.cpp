#include "RecoveryDrive.h"

#include <windows.h>

#include <stdexcept>
#include <system_error>

std::vector<std::filesystem::path>
RecoveryDrive::findRecoveryFiles()
{
    std::vector<std::filesystem::path> results;

    const DWORD driveMask =
        GetLogicalDrives();

    if (driveMask == 0)
    {
        throw std::runtime_error(
            "Cannot enumerate logical drives.");
    }

    for (unsigned int index = 0;
        index < 26;
        ++index)
    {
        if ((driveMask &
            (1UL << index)) == 0)
        {
            continue;
        }

        wchar_t root[] =
        {
            static_cast<wchar_t>(
                L'A' + index),
            L':',
            L'\\',
            L'\0'
        };

        if (GetDriveTypeW(root) !=
            DRIVE_REMOVABLE)
        {
            continue;
        }

        const std::filesystem::path path =
            std::filesystem::path(root) /
            FileName;

        std::error_code error;

        if (std::filesystem::is_regular_file(
            path,
            error) &&
            !error)
        {
            results.push_back(path);
        }
    }

    return results;
}
