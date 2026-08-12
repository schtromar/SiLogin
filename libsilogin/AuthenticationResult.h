#pragma once

#include <optional>
#include <string>
#include <utility>

enum class AuthenticationStatus
{
    Success,
    Rejected,
    InvalidRequest,
    OperationFailed
};

struct AuthenticatedIdentity
{
    std::string accountSid;
    std::string accountName;
    std::string certificateThumbprint;
};

struct AuthenticationResult
{
    AuthenticationStatus status =
        AuthenticationStatus::OperationFailed;

    std::string message;

    std::optional<AuthenticatedIdentity> identity;

    bool succeeded() const noexcept
    {
        return status == AuthenticationStatus::Success;
    }

    explicit operator bool() const noexcept
    {
        return succeeded();
    }

    static AuthenticationResult success(
        std::string message,
        std::optional<AuthenticatedIdentity> identity =
        std::nullopt)
    {
        return {
            AuthenticationStatus::Success,
            std::move(message),
            std::move(identity)
        };
    }

    static AuthenticationResult rejected(
        std::string message)
    {
        return {
            AuthenticationStatus::Rejected,
            std::move(message),
            std::nullopt
        };
    }

    static AuthenticationResult invalidRequest(
        std::string message)
    {
        return {
            AuthenticationStatus::InvalidRequest,
            std::move(message),
            std::nullopt
        };
    }

    static AuthenticationResult failed(
        std::string message)
    {
        return {
            AuthenticationStatus::OperationFailed,
            std::move(message),
            std::nullopt
        };
    }
};
