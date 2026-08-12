#pragma once

#include <filesystem>
#include <string>

class Logger;

class AuthenticationWorkflow
{
public:
    explicit AuthenticationWorkflow(
        Logger& logger);

    int enrollCard();

    int authenticateWithCard();

    int authenticateWithCardForAccount(
        const std::string& expectedAccountSid);

    int enrollRecovery(
        const std::filesystem::path& suppliedPath);

    int authenticateWithRecovery();

    int authenticateWithRecoveryForAccount(
        const std::string& expectedAccountSid);

private:
    Logger& logger_;
};
