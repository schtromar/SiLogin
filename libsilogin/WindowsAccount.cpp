#include "WindowsAccount.h"

#include <windows.h>
#include <sddl.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    std::string wideStringToUtf8(const std::wstring& value)
    {
        if (value.empty())
        {
            return {};
        }

        const int requiredBytes = WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0,
            nullptr,
            nullptr);

        if (requiredBytes <= 0)
        {
            throw std::runtime_error(
                "WideCharToMultiByte size query failed.");
        }

        std::string result(
            static_cast<std::size_t>(requiredBytes),
            '\0');

        if (WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            &result[0],
            requiredBytes,
            nullptr,
            nullptr) <= 0)
        {
            throw std::runtime_error(
                "WideCharToMultiByte failed.");
        }

        return result;
    }

    std::runtime_error windowsError(
        const char* operation)
    {
        return std::runtime_error(
            std::string(operation) +
            " failed with Windows error " +
            std::to_string(GetLastError()) +
            ".");
    }

    std::string getCurrentUserName()
    {
        DWORD characterCount = 0;

        GetUserNameW(
            nullptr,
            &characterCount);

        if (characterCount == 0)
        {
            throw windowsError(
                "GetUserNameW size query");
        }

        std::vector<wchar_t> buffer(characterCount);

        if (!GetUserNameW(
            buffer.data(),
            &characterCount))
        {
            throw windowsError("GetUserNameW");
        }

        return wideStringToUtf8(buffer.data());
    }

    std::string getCurrentUserSid()
    {
        HANDLE token = nullptr;

        if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &token))
        {
            throw windowsError(
                "OpenProcessToken");
        }

        try
        {
            DWORD requiredBytes = 0;

            GetTokenInformation(
                token,
                TokenUser,
                nullptr,
                0,
                &requiredBytes);

            if (requiredBytes == 0 ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                throw windowsError(
                    "GetTokenInformation size query");
            }

            std::vector<BYTE> buffer(requiredBytes);

            if (!GetTokenInformation(
                token,
                TokenUser,
                buffer.data(),
                requiredBytes,
                &requiredBytes))
            {
                throw windowsError(
                    "GetTokenInformation");
            }

            const auto* tokenUser =
                reinterpret_cast<const TOKEN_USER*>(
                    buffer.data());

            LPWSTR sidString = nullptr;

            if (!ConvertSidToStringSidW(
                tokenUser->User.Sid,
                &sidString))
            {
                throw windowsError(
                    "ConvertSidToStringSidW");
            }

            try
            {
                const std::string result =
                    wideStringToUtf8(sidString);

                LocalFree(sidString);
                CloseHandle(token);

                return result;
            }
            catch (...)
            {
                LocalFree(sidString);
                throw;
            }
        }
        catch (...)
        {
            CloseHandle(token);
            throw;
        }
    }
}

WindowsAccount WindowsAccount::current()
{
    WindowsAccount account;

    account.userName_ = getCurrentUserName();
    account.sid_ = getCurrentUserSid();

    return account;
}

const std::string& WindowsAccount::userName() const
{
    return userName_;
}

const std::string& WindowsAccount::sid() const
{
    return sid_;
}