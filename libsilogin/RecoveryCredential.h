#pragma once

#include <filesystem>
#include <string>
#include <vector>

class Certificate;
class WindowsAccount;

class RecoveryCredential
{
public:
    static constexpr unsigned int CurrentVersion = 1;

    static RecoveryCredential create(
        const WindowsAccount& account,
        const Certificate& certificate);

    static RecoveryCredential load(
        const std::filesystem::path& path);

    void save(
        const std::filesystem::path& path) const;

    std::string canonicalPayloadJson() const;
    std::vector<unsigned char> canonicalPayload() const;

    const std::string& recoveryId() const;
    const std::string& accountSid() const;
    const std::string& certificateThumbprint() const;
    const std::string& createdAtUtc() const;

private:
    std::string format_ = "SiLogin recovery";
    unsigned int version_ = CurrentVersion;

    std::string recoveryId_;
    std::string secret_;
    std::string accountSid_;
    std::string certificateThumbprint_;
    std::string createdAtUtc_;
};
