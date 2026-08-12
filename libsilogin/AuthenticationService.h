#pragma once

#include "AuthenticationResult.h"

#if defined(__has_include)
#  if __has_include(<filesystem>)
#    include <filesystem>
#  elif __has_include(<experimental/filesystem>)
#    include <experimental/filesystem>
#    define LIBSILOGIN_USE_EXPERIMENTAL_FILESYSTEM
#  else
#    error "<filesystem> or <experimental/filesystem> is required"
#  endif
#else
#  include <filesystem>
#endif
#if defined(LIBSILOGIN_USE_EXPERIMENTAL_FILESYSTEM)
namespace std {
    namespace filesystem = experimental::filesystem;
}
#endif
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
        const std::string& driveRoot) noexcept;

    AuthenticationResult authenticateWithRecovery() noexcept;

    AuthenticationResult authenticateWithRecoveryForAccount(
        const std::string& expectedAccountSid) noexcept;

private:
    Logger& logger_;
};
