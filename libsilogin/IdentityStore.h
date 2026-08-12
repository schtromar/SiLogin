#pragma once

#include "Enrollment.h"

#include <filesystem>
#include <optional>
#include <string>

class IdentityStore
{
public:
    // Uses the current signed-in user's SID. Intended for enrollment tools.
    IdentityStore();

    // Uses a specific Windows account SID. Intended for LogonUI and services.
    explicit IdentityStore(
        std::string accountSid);

    const std::filesystem::path&
        filePath() const;

    std::optional<Enrollment> load() const;

    void save(
        const Enrollment& enrollment) const;

private:
    std::string accountSid_;
    std::filesystem::path directoryPath_;
    std::filesystem::path filePath_;
};
