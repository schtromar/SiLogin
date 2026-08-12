#pragma once

#include "LoggerAware.h"

#include <windows.h>
#include <winscard.h>

#include <string>
#include <vector>

struct SmartCardInformation
{
    std::string readerName;
    std::string atrHex;
    std::string protocolName;
};

class SmartCard : protected LoggerAware
{
public:
    explicit SmartCard(
        Logger& logger);

    ~SmartCard();

    SmartCard(
        const SmartCard&) = delete;

    SmartCard& operator=(
        const SmartCard&) = delete;

    SmartCard(
        SmartCard&&) = delete;

    SmartCard& operator=(
        SmartCard&&) = delete;

    bool initialize();
    bool waitForInsertion();
    bool waitForRemoval();
    bool connect();
    void disconnect();

    std::vector<std::string>
        readerNames() const;

    SmartCardInformation
        cardInformation() const;

private:
    static DWORD normalizedState(
        DWORD state);

    bool getInitialReaderState(
        SCARD_READERSTATEA& readerState) const;

    void cleanUp();

    SCARDCONTEXT context_ = 0;
    SCARDHANDLE card_ = 0;
    DWORD protocol_ = 0;
    char* readers_ = nullptr;
};
