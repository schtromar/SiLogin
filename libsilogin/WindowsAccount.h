#pragma once

#include <string>

class WindowsAccount
{
public:
    static WindowsAccount current();

    const std::string& userName() const;
    const std::string& sid() const;

private:
    std::string userName_;
    std::string sid_;
};