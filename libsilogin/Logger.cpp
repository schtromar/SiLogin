#include "Logger.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

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

    std::string currentUtcTimestamp()
    {
        const auto now =
            std::chrono::system_clock::now();

        const auto milliseconds =
            std::chrono::duration_cast<
            std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

        const std::time_t time =
            std::chrono::system_clock::to_time_t(
                now);

        std::tm utc{};

        if (gmtime_s(
            &utc,
            &time) != 0)
        {
            return "unknown-time";
        }

        std::ostringstream output;

        output
            << std::put_time(
                &utc,
                "%Y-%m-%dT%H:%M:%S")
            << '.'
            << std::setfill('0')
            << std::setw(3)
            << milliseconds.count()
            << 'Z';

        return output.str();
    }

    std::string formatEntry(
        LogLevel level,
        const std::string& timestampUtc,
        const std::string& message)
    {
        const std::string prefix =
            timestampUtc +
            " [" +
            logLevelName(level) +
            "] ";

        std::istringstream input(message);
        std::ostringstream output;
        std::string line;
        bool wroteLine = false;

        while (std::getline(input, line))
        {
            output
                << prefix
                << line
                << '\n';

            wroteLine = true;
        }

        if (!wroteLine)
        {
            output
                << prefix
                << '\n';
        }

        return output.str();
    }
}

const char* logLevelName(
    LogLevel level)
{
    switch (level)
    {
    case LogLevel::Trace:
        return "Trace";

    case LogLevel::Debug:
        return "Debug";

    case LogLevel::Information:
        return "Information";

    case LogLevel::Warning:
        return "Warning";

    case LogLevel::Error:
        return "Error";

    case LogLevel::Critical:
        return "Critical";

    case LogLevel::None:
        return "None";
    }

    return "Unknown";
}

LogLevel parseLogLevel(
    const std::string& value)
{
    const std::string normalized =
        lowercase(value);

    if (normalized == "trace")
    {
        return LogLevel::Trace;
    }

    if (normalized == "debug")
    {
        return LogLevel::Debug;
    }

    if (normalized == "information" ||
        normalized == "info")
    {
        return LogLevel::Information;
    }

    if (normalized == "warning" ||
        normalized == "warn")
    {
        return LogLevel::Warning;
    }

    if (normalized == "error")
    {
        return LogLevel::Error;
    }

    if (normalized == "critical" ||
        normalized == "fatal")
    {
        return LogLevel::Critical;
    }

    if (normalized == "none" ||
        normalized == "off")
    {
        return LogLevel::None;
    }

    throw std::runtime_error(
        "Unknown verbosity level: " +
        value);
}

Logger::Logger(
    LogLevel defaultLevel)
    : minimumLevel_(
        defaultLevel)
{
}

void Logger::setMinimumLevel(
    LogLevel minimumLevel)
{
    std::lock_guard<std::mutex> lock(
        mutex_);

    minimumLevel_ =
        minimumLevel;
}

LogLevel Logger::minimumLevel() const
{
    std::lock_guard<std::mutex> lock(
        mutex_);

    return minimumLevel_;
}

void Logger::addSink(
    std::shared_ptr<ILogSink> sink)
{
    if (!sink)
    {
        throw std::invalid_argument(
            "Log sink cannot be null.");
    }

    std::lock_guard<std::mutex> lock(
        mutex_);

    sinks_.push_back(
        std::move(sink));
}

bool Logger::isEnabled(
    LogLevel level) const
{
    std::lock_guard<std::mutex> lock(
        mutex_);

    return
        minimumLevel_ != LogLevel::None &&
        level >= minimumLevel_;
}

void Logger::trace(
    const std::string& message)
{
    log(
        LogLevel::Trace,
        message);
}

void Logger::debug(
    const std::string& message)
{
    log(
        LogLevel::Debug,
        message);
}

void Logger::message(
    const std::string& message)
{
    log(
        LogLevel::Information,
        message);
}

void Logger::information(
    const std::string& message)
{
    log(
        LogLevel::Information,
        message);
}

void Logger::warning(
    const std::string& message)
{
    log(
        LogLevel::Warning,
        message);
}

void Logger::error(
    const std::string& message)
{
    log(
        LogLevel::Error,
        message);
}

void Logger::critical(
    const std::string& message)
{
    log(
        LogLevel::Critical,
        message);
}

void Logger::log(
    LogLevel level,
    const std::string& message)
{
    std::lock_guard<std::mutex> lock(
        mutex_);

    if (minimumLevel_ == LogLevel::None ||
        level < minimumLevel_)
    {
        return;
    }

    const std::string timestamp =
        currentUtcTimestamp();

    for (const auto& sink :
        sinks_)
    {
        sink->write(
            level,
            timestamp,
            message);
    }
}

void ConsoleLogSink::write(
    LogLevel level,
    const std::string& timestampUtc,
    const std::string& message)
{
    std::ostream& output =
        level >= LogLevel::Error
        ? std::cerr
        : std::cout;

    output
        << formatEntry(
            level,
            timestampUtc,
            message);

    output.flush();
}

void DebugLogSink::write(
    LogLevel level,
    const std::string& timestampUtc,
    const std::string& message)
{
    const std::string entry =
        formatEntry(
            level,
            timestampUtc,
            message);

    OutputDebugStringA(
        entry.c_str());
}
