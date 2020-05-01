#ifndef NTPESK_NTPRSK_H
#define NTPESK_NTPRSK_H

#include "NtpRskSignatureVerificationObject.h"
#include "NtpRskSignatureRequestObject.h"

class NtpRsk {
    public:
        static NtpRskSignatureVerificationObject *signWithNtpRsk(NtpRskSignatureRequestObject *ntpEskSignatureRequestObject);
        static bool verifyNtpRsk(NtpRskSignatureVerificationObject *ntpEskSignatureVerificationObject);
    private:
        static BIGNUM* randomBignum(const BIGNUM* maxSize);
};


#endif //NTPESK_NTPRSK_H
