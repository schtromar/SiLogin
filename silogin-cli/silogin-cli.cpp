// silogin-cli.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../libsilogin/framework.h"
#include "../libsilogin/CommandLine.h"
#include "../libsilogin/Logger.h"
#include "../libsilogin/AuthenticationService.h"
#include "../libsilogin/AuthenticationResult.h"

#include <windows.h>

#include <exception>
#include <memory>
#include <string>

namespace
{
    void addDefaultSinks(Logger& logger)
    {
        logger.addSink(
            std::make_shared<ConsoleLogSink>());

#ifdef _DEBUG
        logger.addSink(
            std::make_shared<DebugLogSink>());
#endif
    }

    int exitCode(const AuthenticationResult& result)
    {
        switch (result.status)
        {
        case AuthenticationStatus::Success:
            return 0;

        case AuthenticationStatus::Rejected:
            return 2;

        case AuthenticationStatus::InvalidRequest:
            return 3;

        case AuthenticationStatus::OperationFailed:
            return 1;
        }

        return 1;
    }
}

int main(int argumentCount, char* arguments[])
{
    SetConsoleOutputCP(CP_UTF8);

    Logger logger(LogLevel::Information);
    addDefaultSinks(logger);

    try
    {
        const CommandLine commandLine =
            CommandLine::parse(argumentCount, arguments);

        logger.setMinimumLevel(commandLine.verbosity());

        AuthenticationService service(logger);
        AuthenticationResult result;

        switch (commandLine.mode())
        {
        case ProgramMode::Enroll:
            result = service.enrollCard();
            break;

        case ProgramMode::Authenticate:
            result = service.authenticateWithCard();
            break;

        case ProgramMode::EnrollRecovery:
            result = service.enrollRecovery(
                commandLine.recoveryDrive());
            break;

        case ProgramMode::AlternateAuthenticate:
            result = service.authenticateWithRecovery();
            break;
        }

        if (!result.succeeded() && !result.message.empty())
        {
            logger.error(result.message);
        }

        return exitCode(result);
    }
    catch (const std::exception& exception)
    {
        logger.critical(
            std::string("Fatal command-line error: ") +
            exception.what());

        logger.message(CommandLine::usage());
        return 3;
    }
}
