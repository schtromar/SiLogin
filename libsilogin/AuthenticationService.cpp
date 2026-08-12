#include "AuthenticationService.h"

#include "AuthenticationWorkflow.h"
#include "IdentityStore.h"
#include "Logger.h"

#include <exception>
#include <optional>
#include <stdexcept>
#include <string>

namespace
{
    template<typename Operation>
    AuthenticationResult executeOperation(
        Logger& logger,
        const char* operationName,
        Operation&& operation) noexcept
    {
        try
        {
            return operation();
        }
        catch (const std::invalid_argument& exception)
        {
            logger.error(
                std::string(operationName) +
                " received an invalid request: " +
                exception.what());

            return AuthenticationResult::invalidRequest(
                exception.what());
        }
        catch (const std::exception& exception)
        {
            logger.error(
                std::string(operationName) +
                " failed: " +
                exception.what());

            return AuthenticationResult::failed(
                exception.what());
        }
        catch (...)
        {
            logger.critical(
                std::string(operationName) +
                " failed with an unknown exception.");

            return AuthenticationResult::failed(
                "An unknown authentication error occurred.");
        }
    }

    AuthenticationResult resultForAccount(
        const std::string& accountSid,
        const char* successMessage,
        int workflowResult)
    {
        if (workflowResult != 0)
        {
            return AuthenticationResult::rejected(
                "The second-factor credential was rejected.");
        }

        const IdentityStore store(
            accountSid);

        const std::optional<Enrollment> enrollment =
            store.load();

        if (!enrollment.has_value())
        {
            return AuthenticationResult::failed(
                "The authenticated enrollment could not be reloaded.");
        }

        auto identity = std::make_unique<AuthenticatedIdentity>();

        identity->accountSid =
            enrollment->accountSid;

        identity->accountName =
            enrollment->accountName;

        identity->certificateThumbprint =
            enrollment->certificateThumbprint;

        return AuthenticationResult::success(
            successMessage,
            std::move(identity));
    }
}

AuthenticationService::AuthenticationService(
    Logger& logger) noexcept
    : logger_(logger)
{
}

AuthenticationResult
AuthenticationService::enrollCard() noexcept
{
    return executeOperation(
        logger_,
        "Card enrollment",
        [this]()
        {
            AuthenticationWorkflow workflow(
                logger_);

            return workflow.enrollCard() == 0
                ? AuthenticationResult::success(
                    "Card enrollment completed successfully.")
                : AuthenticationResult::rejected(
                    "Card enrollment was not completed.");
        });
}

AuthenticationResult
AuthenticationService::authenticateWithCard() noexcept
{
    return executeOperation(
        logger_,
        "Card authentication",
        [this]()
        {
            AuthenticationWorkflow workflow(
                logger_);

            const int result =
                workflow.authenticateWithCard();

            if (result != 0)
            {
                return AuthenticationResult::rejected(
                    "Card authentication was not completed.");
            }

            return AuthenticationResult::success(
                "Card authentication completed successfully.");
        });
}

AuthenticationResult
AuthenticationService::authenticateWithCardForAccount(
    const std::string& expectedAccountSid) noexcept
{
    if (expectedAccountSid.empty())
    {
        return AuthenticationResult::invalidRequest(
            "An expected account SID is required.");
    }

    return executeOperation(
        logger_,
        "Card authentication",
        [this, &expectedAccountSid]()
        {
            AuthenticationWorkflow workflow(
                logger_);

            return resultForAccount(
                expectedAccountSid,
                "Card authentication completed successfully.",
                workflow.authenticateWithCardForAccount(
                    expectedAccountSid));
        });
}

AuthenticationResult
AuthenticationService::enrollRecovery(
    const std::string& driveRoot) noexcept
{
    if (driveRoot.empty())
    {
        return AuthenticationResult::invalidRequest(
            "A recovery drive root is required.");
    }

    return executeOperation(
        logger_,
        "Recovery enrollment",
        [this, &driveRoot]()
        {
            AuthenticationWorkflow workflow(
                logger_);

            return workflow.enrollRecovery(
                driveRoot) == 0
                ? AuthenticationResult::success(
                    "Recovery enrollment completed successfully.")
                : AuthenticationResult::rejected(
                    "Recovery enrollment was not completed.");
        });
}

AuthenticationResult
AuthenticationService::authenticateWithRecovery() noexcept
{
    return executeOperation(
        logger_,
        "Recovery authentication",
        [this]()
        {
            AuthenticationWorkflow workflow(
                logger_);

            return workflow.authenticateWithRecovery() == 0
                ? AuthenticationResult::success(
                    "Recovery authentication completed successfully.")
                : AuthenticationResult::rejected(
                    "Recovery authentication was not completed.");
        });
}

AuthenticationResult
AuthenticationService::authenticateWithRecoveryForAccount(
    const std::string& expectedAccountSid) noexcept
{
    if (expectedAccountSid.empty())
    {
        return AuthenticationResult::invalidRequest(
            "An expected account SID is required.");
    }

    return executeOperation(
        logger_,
        "Recovery authentication",
        [this, &expectedAccountSid]()
        {
            AuthenticationWorkflow workflow(
                logger_);

            return resultForAccount(
                expectedAccountSid,
                "Recovery authentication completed successfully.",
                workflow.authenticateWithRecoveryForAccount(
                    expectedAccountSid));
        });
}
