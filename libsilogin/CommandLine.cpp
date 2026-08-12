#include "CommandLine.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    std::string lowercase(
        std::string value)
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char character)
            {
                return static_cast<char>(
                    std::tolower(character));
            });

        return value;
    }
}

CommandLine CommandLine::parse(
    int argumentCount,
    char* arguments[])
{
    CommandLine result;

    std::vector<std::string> positionalArguments;

    for (int index = 1;
         index < argumentCount;
         ++index)
    {
        const std::string argument =
            arguments[index];

        if (argument == "--verbosity" ||
            argument == "-v")
        {
            if (index + 1 >=
                argumentCount)
            {
                throw std::runtime_error(
                    "--verbosity requires a level.");
            }

            result.verbosity_ =
                parseLogLevel(
                    arguments[++index]);

            continue;
        }

        constexpr const char* prefix =
            "--verbosity=";

        if (argument.rfind(
                prefix,
                0) == 0)
        {
            result.verbosity_ =
                parseLogLevel(
                    argument.substr(
                        std::char_traits<char>::length(
                            prefix)));

            continue;
        }

        positionalArguments.push_back(
            argument);
    }

    if (positionalArguments.empty())
    {
        throw std::runtime_error(
            "A command is required.");
    }

    const std::string command =
        lowercase(
            positionalArguments[0]);

    if (command == "enroll")
    {
        if (positionalArguments.size() != 1)
        {
            throw std::runtime_error(
                "The enroll command takes no arguments.");
        }

        result.mode_ =
            ProgramMode::Enroll;

        return result;
    }

    if (command == "authenticate")
    {
        if (positionalArguments.size() != 1)
        {
            throw std::runtime_error(
                "The authenticate command takes no arguments.");
        }

        result.mode_ =
            ProgramMode::Authenticate;

        return result;
    }

    if (command == "enrollrecovery")
    {
        if (positionalArguments.size() != 2)
        {
            throw std::runtime_error(
                "enrollRecovery requires a drive root.");
        }

        result.mode_ =
            ProgramMode::EnrollRecovery;

        result.recoveryDrive_ =
            positionalArguments[1];

        return result;
    }

    if (command == "altauthenticate")
    {
        if (positionalArguments.size() != 1)
        {
            throw std::runtime_error(
                "altAuthenticate takes no arguments.");
        }

        result.mode_ =
            ProgramMode::AlternateAuthenticate;

        return result;
    }

    throw std::runtime_error(
        "Unknown command: " +
        positionalArguments[0]);
}

ProgramMode CommandLine::mode() const
{
    return mode_;
}

LogLevel CommandLine::verbosity() const
{
    return verbosity_;
}

const std::filesystem::path&
CommandLine::recoveryDrive() const
{
    return recoveryDrive_;
}

const char* CommandLine::usage()
{
    return
        "Usage:\n"
        "  SmartCardLogin.exe [--verbosity <level>] enroll\n"
        "  SmartCardLogin.exe [--verbosity <level>] authenticate\n"
        "  SmartCardLogin.exe [--verbosity <level>] "
        "enrollRecovery <drive-root>\n"
        "  SmartCardLogin.exe [--verbosity <level>] "
        "altAuthenticate\n"
        "\n"
        "Levels:\n"
        "  trace, debug, information, warning, error, "
        "critical, none\n";
}
