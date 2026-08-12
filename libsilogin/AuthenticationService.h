#pragma once

#include "AuthenticationResult.h"

#include <filesystem>
#include <string>

class Logger;

class AuthenticationService final
{
public:
    explicit AuthenticationService(
        Logger& logger) noexcept;

    AuthenticationResult enrollCard() noexcept;

    AuthenticationResult authenticateWithCard() noexcept;

    AuthenticationResult authenticateWithCardForAccount(
        const std::string& expectedAccountSid) noexcept;

    AuthenticationResult enrollRecovery(
        const std::filesystem::path& driveRoot) noexcept;

    AuthenticationResult authenticateWithRecovery() noexcept;

    AuthenticationResult authenticateWithRecoveryForAccount(
        const std::string& expectedAccountSid) noexcept;

private:
    Logger& logger_;
};
