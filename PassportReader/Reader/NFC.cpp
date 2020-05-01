#include "NFC.h"
#include "../../Tools/Log.h"

int NFC::modus = NO_MODUS;
SCARDHANDLE NFC::hCard;
const SCARD_IO_REQUEST* NFC::pioSendPci = nullptr;

bool NFC::transmit(uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t* rapdulen) {
    int res;
    size_t  szPos;

    if(NFC::modus == NO_MODUS) {
        if(NFC::getCard() != nullptr) NFC::modus = PCSC_MODUS;
    }

    if(NFC::modus == PCSC_MODUS) {
        DWORD rapdulenDWORD = *rapdulen;
        printf("=> ");
        for (szPos = 0; szPos < capdulen; szPos++) {
            printf("%02x ", capdu[szPos]);
        }
        printf("\n");

        LONG rv;
        if (NFC::getCard() != nullptr) {
            rv = SCardTransmit(*NFC::getCard(), NFC::pioSendPci, capdu, capdulen,
                               NULL, rapdu, &rapdulenDWORD);
            printf("<= ");
            *rapdulen = (size_t) rapdulenDWORD;
            for (szPos = 0; szPos < *rapdulen; szPos++) {
                printf("%02x ", rapdu[szPos]);
            }
            Log(LOG_LEVEL_INFO) << "rapdulen: " << rapdulen;
            Log(LOG_LEVEL_INFO) << "rv: " << (uint32_t)rv;
            if (rv >= 0) {
                return true;
            }
        } else {
            printf("Failed to getCard\n");
        }
        return false;
    }

    return false;
}

void NFC::close() {
    NFC::modus = NO_MODUS;
    NFC::hCard = NULL;
}

SCARDHANDLE* NFC::getCard() {
    if (NFC::hCard) {
        return &NFC::hCard;
    }

    LONG rv;
    DWORD dwReaders, dwActiveProtocol;
    SCARDCONTEXT hContext;
    LPCSTR mszReaders;
    SCARDHANDLE hCardHandle;

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

    if (rv != SCARD_S_SUCCESS) {
        Log(LOG_LEVEL_ERROR) << "cannot establish SCard context, rv:" << (uint32_t) rv;
        return nullptr;
    }

#ifdef SCARD_AUTOALLOCATE
    dwReaders = SCARD_AUTOALLOCATE;

    rv = SCardListReaders(hContext, NULL, (LPSTR) &mszReaders, &dwReaders);
#else
    rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
    calloc(dwReaders, sizeof(char));
    rv = SCardListReaders(hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
#endif

    if (rv != SCARD_S_SUCCESS) {
        Log(LOG_LEVEL_ERROR) << "cannot list NFC Reader, rv:" << (uint32_t) rv;
        return nullptr;
    }

    printf("reader name: %s\n", mszReaders);

    rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &NFC::hCard, &dwActiveProtocol);

    switch (dwActiveProtocol) {
        case SCARD_PROTOCOL_T0:
            NFC::pioSendPci = SCARD_PCI_T0;
            break;

        case SCARD_PROTOCOL_T1:
            NFC::pioSendPci = SCARD_PCI_T1;
            break;
    }

    return &NFC::hCard;
}
