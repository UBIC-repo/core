
#ifndef UBICD_CERTHELPER_H
#define UBICD_CERTHELPER_H

#include <openssl/x509.h>

class CertHelper {
public:
    static uint8_t getCurrencyIdForCert(X509* x509);
    static uint64_t calculateDSCExpirationDateForCert(X509* x509);
    static time_t ASN1_GetTimeT(ASN1_TIME* time);
};


#endif //UBICD_CERTHELPER_H
