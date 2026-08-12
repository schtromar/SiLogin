#pragma once

#include "Logger.h"

#include <filesystem>

enum class ProgramMode
{
    Enroll,
    Authenticate,
    EnrollRecovery,
    AlternateAuthenticate
};

class CommandLine
{
public:
    static CommandLine parse(
        int argumentCount,
        char* arguments[]);

    ProgramMode mode() const;
    LogLevel verbosity() const;

    const std::filesystem::path&
        recoveryDrive() const;

    static const char* usage();

private:
    ProgramMode mode_ =
        ProgramMode::Authenticate;

    LogLevel verbosity_ =
#ifdef _DEBUG
        LogLevel::Debug;
#else
        LogLevel::Information;
#endif

    std::filesystem::path recoveryDrive_;
};
