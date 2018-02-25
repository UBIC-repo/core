
#ifndef NTPESK_NTPESK_H
#define NTPESK_NTPESK_H

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include "NtpEskSignatureVerificationObject.h"
#include "NtpEskSignatureRequestObject.h"

class NtpEsk {
    public:
        static NtpEskSignatureVerificationObject *signWithNtpEsk(NtpEskSignatureRequestObject *ntpEskSignatureRequestObject);
        static bool verifyNtpEsk(NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject);
    private:
        static BIGNUM* randomBignum(BIGNUM* maxSize);
};


#endif //NTPESK_NTPESK_H
