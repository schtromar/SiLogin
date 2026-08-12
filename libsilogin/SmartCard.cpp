#include "SmartCard.h"

#include "Logger.h"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace
{
    std::string smartCardError(
        const char* operation,
        LONG result)
    {
        std::ostringstream output;

        output
            << operation
            << " failed with PC/SC error 0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(result)
            << std::dec
            << '.';

        return output.str();
    }

    bool stateHasError(
        DWORD state)
    {
        return
            (state & SCARD_STATE_UNKNOWN) != 0 ||
            (state & SCARD_STATE_UNAVAILABLE) != 0;
    }

    std::string protocolName(
        DWORD protocol)
    {
        switch (protocol)
        {
        case SCARD_PROTOCOL_T0:
            return "T=0";

        case SCARD_PROTOCOL_T1:
            return "T=1";

        default:
            return std::to_string(protocol);
        }
    }

    std::string bytesToHex(
        const BYTE* bytes,
        DWORD length)
    {
        std::ostringstream output;

        output
            << std::hex
            << std::uppercase
            << std::setfill('0');

        for (DWORD index = 0;
             index < length;
             ++index)
        {
            if (index != 0)
            {
                output << ' ';
            }

            output
                << std::setw(2)
                << static_cast<unsigned int>(
                    bytes[index]);
        }

        return output.str();
    }
}

SmartCard::SmartCard(
    Logger& logger)
    : LoggerAware(
        logger)
{
}

SmartCard::~SmartCard()
{
    cleanUp();
}

DWORD SmartCard::normalizedState(
    DWORD state)
{
    // SCARD_STATE_CHANGED describes why SCardGetStatusChange
    // returned. It is not part of the persistent reader state.
    return state & ~SCARD_STATE_CHANGED;
}

void SmartCard::disconnect()
{
    if (card_ == 0)
    {
        return;
    }

    const LONG result =
        SCardDisconnect(
            card_,
            SCARD_LEAVE_CARD);

    if (result != SCARD_S_SUCCESS)
    {
        logger_.error(
            smartCardError(
                "SCardDisconnect",
                result));
    }
    else
    {
        logger_.debug(
            "Disconnected from the smart card.");
    }

    card_ = 0;
    protocol_ = 0;
}

void SmartCard::cleanUp()
{
    disconnect();

    if (readers_ != nullptr &&
        context_ != 0)
    {
        const LONG result =
            SCardFreeMemory(
                context_,
                readers_);

        if (result != SCARD_S_SUCCESS)
        {
            logger_.warning(
                smartCardError(
                    "SCardFreeMemory",
                    result));
        }

        readers_ = nullptr;
    }

    if (context_ != 0)
    {
        const LONG result =
            SCardReleaseContext(
                context_);

        if (result != SCARD_S_SUCCESS)
        {
            logger_.warning(
                smartCardError(
                    "SCardReleaseContext",
                    result));
        }

        context_ = 0;
    }
}

bool SmartCard::initialize()
{
    cleanUp();

    LONG result =
        SCardEstablishContext(
            SCARD_SCOPE_USER,
            nullptr,
            nullptr,
            &context_);

    if (result != SCARD_S_SUCCESS)
    {
        logger_.error(
            smartCardError(
                "SCardEstablishContext",
                result));

        return false;
    }

    DWORD readersLength =
        SCARD_AUTOALLOCATE;

    result =
        SCardListReadersA(
            context_,
            nullptr,
            reinterpret_cast<LPSTR>(
                &readers_),
            &readersLength);

    if (result != SCARD_S_SUCCESS)
    {
        logger_.error(
            smartCardError(
                "SCardListReadersA",
                result));

        cleanUp();
        return false;
    }

    if (readers_ == nullptr ||
        readers_[0] == '\0')
    {
        logger_.error(
            "Windows returned an empty smart-card "
            "reader list.");

        cleanUp();
        return false;
    }

    const std::vector<std::string> names =
        readerNames();

    logger_.debug(
        "Smart-card subsystem initialized with " +
        std::to_string(names.size()) +
        " reader(s).");

    for (const std::string& name : names)
    {
        logger_.debug(
            "Smart-card reader: " +
            name +
            ".");
    }

    return true;
}

bool SmartCard::getInitialReaderState(
    SCARD_READERSTATEA& readerState) const
{
    if (context_ == 0)
    {
        logger_.error(
            "SmartCard::initialize() must be called "
            "before reading card state.");

        return false;
    }

    if (readers_ == nullptr ||
        readers_[0] == '\0')
    {
        logger_.error(
            "No smart-card reader is available.");

        return false;
    }

    readerState = {};
    readerState.szReader = readers_;
    readerState.dwCurrentState =
        SCARD_STATE_UNAWARE;

    const LONG result =
        SCardGetStatusChangeA(
            context_,
            INFINITE,
            &readerState,
            1);

    if (result != SCARD_S_SUCCESS)
    {
        logger_.error(
            smartCardError(
                "SCardGetStatusChangeA",
                result));

        return false;
    }

    if (stateHasError(
            readerState.dwEventState))
    {
        logger_.error(
            "The smart-card reader is unavailable "
            "or no longer recognized.");

        return false;
    }

    return true;
}

bool SmartCard::waitForInsertion()
{
    SCARD_READERSTATEA readerState{};

    if (!getInitialReaderState(
            readerState))
    {
        return false;
    }

    if ((readerState.dwEventState &
         SCARD_STATE_PRESENT) != 0)
    {
        logger_.debug(
            "A smart card is already present.");

        return true;
    }

    readerState.dwCurrentState =
        normalizedState(
            readerState.dwEventState);

    logger_.trace(
        "Waiting for smart-card insertion.");

    while (true)
    {
        const LONG result =
            SCardGetStatusChangeA(
                context_,
                INFINITE,
                &readerState,
                1);

        if (result != SCARD_S_SUCCESS)
        {
            logger_.error(
                smartCardError(
                    "SCardGetStatusChangeA",
                    result));

            return false;
        }

        if (stateHasError(
                readerState.dwEventState))
        {
            logger_.error(
                "The smart-card reader became "
                "unavailable while waiting for insertion.");

            return false;
        }

        if ((readerState.dwEventState &
             SCARD_STATE_PRESENT) != 0)
        {
            logger_.debug(
                "Smart-card insertion detected.");

            return true;
        }

        readerState.dwCurrentState =
            normalizedState(
                readerState.dwEventState);
    }
}

bool SmartCard::waitForRemoval()
{
    SCARD_READERSTATEA readerState{};

    if (!getInitialReaderState(
            readerState))
    {
        return false;
    }

    if ((readerState.dwEventState &
         SCARD_STATE_EMPTY) != 0)
    {
        logger_.debug(
            "The smart-card reader is already empty.");

        return true;
    }

    readerState.dwCurrentState =
        normalizedState(
            readerState.dwEventState);

    logger_.trace(
        "Waiting for smart-card removal.");

    while (true)
    {
        const LONG result =
            SCardGetStatusChangeA(
                context_,
                INFINITE,
                &readerState,
                1);

        if (result != SCARD_S_SUCCESS)
        {
            logger_.error(
                smartCardError(
                    "SCardGetStatusChangeA",
                    result));

            return false;
        }

        if (stateHasError(
                readerState.dwEventState))
        {
            logger_.error(
                "The smart-card reader became "
                "unavailable while waiting for removal.");

            return false;
        }

        if ((readerState.dwEventState &
             SCARD_STATE_EMPTY) != 0)
        {
            logger_.debug(
                "Smart-card removal detected.");

            return true;
        }

        readerState.dwCurrentState =
            normalizedState(
                readerState.dwEventState);
    }
}

bool SmartCard::connect()
{
    if (context_ == 0 ||
        readers_ == nullptr)
    {
        logger_.error(
            "SmartCard::initialize() must be called "
            "before connecting to a card.");

        return false;
    }

    if (card_ != 0)
    {
        logger_.debug(
            "The smart card is already connected.");

        return true;
    }

    const char* firstReader =
        readers_;

    const LONG result =
        SCardConnectA(
            context_,
            firstReader,
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 |
                SCARD_PROTOCOL_T1,
            &card_,
            &protocol_);

    if (result != SCARD_S_SUCCESS)
    {
        logger_.error(
            smartCardError(
                "SCardConnectA",
                result));

        card_ = 0;
        protocol_ = 0;

        return false;
    }

    logger_.debug(
        "Connected to the smart card using reader " +
        std::string(firstReader) +
        ".");

    return true;
}

std::vector<std::string>
SmartCard::readerNames() const
{
    std::vector<std::string> names;

    if (readers_ == nullptr)
    {
        return names;
    }

    const char* currentReader =
        readers_;

    while (*currentReader != '\0')
    {
        names.emplace_back(
            currentReader);

        currentReader +=
            std::strlen(currentReader) + 1;
    }

    return names;
}

SmartCardInformation
SmartCard::cardInformation() const
{
    if (card_ == 0)
    {
        throw std::runtime_error(
            "No smart card is connected.");
    }

    BYTE atr[64]{};
    DWORD atrLength =
        sizeof(atr);

    DWORD state = 0;
    DWORD activeProtocol =
        protocol_;

    char readerName[256]{};
    DWORD readerNameLength =
        sizeof(readerName);

    const LONG result =
        SCardStatusA(
            card_,
            readerName,
            &readerNameLength,
            &state,
            &activeProtocol,
            atr,
            &atrLength);

    if (result != SCARD_S_SUCCESS)
    {
        const std::string message =
            smartCardError(
                "SCardStatusA",
                result);

        logger_.error(
            message);

        throw std::runtime_error(
            message);
    }

    SmartCardInformation information;
    information.readerName =
        readerName;
    information.atrHex =
        bytesToHex(
            atr,
            atrLength);
    information.protocolName =
        ::protocolName(
            activeProtocol);

    return information;
}
