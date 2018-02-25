/**
 *
 * Replaced by PSCS
 *
 */
#ifndef PASSPORTREADER_NFC_H
#define PASSPORTREADER_NFC_H

#include <stdlib.h>
#include <cstdint>

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif
#define NO_MODUS 0
#define PCSC_MODUS 1
#define LIBNFC_MODUS 2

class NFC {
public:
    static bool transmit(uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen);
    static void close();
private:
    static int modus;
    static const SCARD_IO_REQUEST* pioSendPci;
    static SCARDHANDLE hCard;
    static SCARDHANDLE* getCard();
};


#endif //PASSPORTREADER_NFC_H
