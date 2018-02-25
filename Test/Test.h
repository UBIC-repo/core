
#ifndef TX_TEST_H
#define TX_TEST_H


#include "../BlockHeader.h"

class Test {
public:
    static uint8_t getCurrencyIdFromIso2Code(char* iso2code);
    static time_t ASN1_GetTimeT(ASN1_TIME* time);
    static void importCACerts(BlockHeader* header);
    static void importDSCCerts(BlockHeader* header);
};


#endif //TX_TEST_H
