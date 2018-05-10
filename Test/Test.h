
#ifndef TX_TEST_H
#define TX_TEST_H


#include "../BlockHeader.h"

class Test {
public:
    static uint8_t getCurrencyIdFromIso2Code(char* iso2code);
    static time_t ASN1_GetTimeT(ASN1_TIME* time);
    static void importCACerts();
    static void importDSCCerts();
};


#endif //TX_TEST_H
