#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

enum class LogLevel
{
    Trace = 0,
    Debug = 1,
    Information = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    None = 6
};

const char* logLevelName(
    LogLevel level);

LogLevel parseLogLevel(
    const std::string& value);

class ILogSink
{
public:
    virtual ~ILogSink() = default;

    virtual void write(
        LogLevel level,
        const std::string& timestampUtc,
        const std::string& message) = 0;
};

class Logger
{
public:
    explicit Logger(
        LogLevel defaultLevel =
        LogLevel::Information);

    void setMinimumLevel(
        LogLevel minimumLevel);

    LogLevel minimumLevel() const;

    void addSink(
        std::shared_ptr<ILogSink> sink);

    bool isEnabled(
        LogLevel level) const;

    void trace(
        const std::string& message);

    void debug(
        const std::string& message);

    // User-facing non-error output uses Information.
    void message(
        const std::string& message);

    void information(
        const std::string& message);

    void warning(
        const std::string& message);

    void error(
        const std::string& message);

    void critical(
        const std::string& message);

private:
    void log(
        LogLevel level,
        const std::string& message);

    mutable std::mutex mutex_;
    LogLevel minimumLevel_;
    std::vector<std::shared_ptr<ILogSink>> sinks_;
};

class ConsoleLogSink final :
    public ILogSink
{
public:
    void write(
        LogLevel level,
        const std::string& timestampUtc,
        const std::string& message) override;
};

class DebugLogSink final :
    public ILogSink
{
public:
    void write(
        LogLevel level,
        const std::string& timestampUtc,
        const std::string& message) override;
};
