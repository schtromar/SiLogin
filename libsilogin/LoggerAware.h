#pragma once

class Logger;

class LoggerAware
{
protected:
    explicit LoggerAware(
        Logger& logger)
        : logger_(logger)
    {
    }

    Logger& logger_;
};
