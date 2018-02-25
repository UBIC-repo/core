/**
 *
 * The PKCS7 element contained in the EF.SOD file of the passport contains element such as
 * - The Document Signing Certificate
 * - The hashes of all other Files contained on the passport.
 * - A Digital signature on those hashes using the Document Signing Certificate
 * The PKCS7Parser is responsible for recovering those elements.
 * See Doc9303 for more information
 *
 */

#ifndef PASSPORTREADER_PKCS7PARSER_H
#define PASSPORTREADER_PKCS7PARSER_H

#include <openssl/pkcs7.h>
#include "../../NtpRsk/NtpRsk.h"
#include "../../NtpEsk/NtpEsk.h"

using namespace std;

class PKCS7Parser {
private:
    PKCS7* p7 = NULL;
    void pkcs7MsgSigDigest(PKCS7* p7, unsigned char *dig, unsigned int *diglen);
public:
    PKCS7Parser(char* sod, size_t sodSize);
    X509* getDscCertificate();
    bool hasError();
    bool isECDSA();
    bool isRSA();
    NtpRskSignatureRequestObject* getNtpRsk();
    NtpEskSignatureRequestObject* getNtpEsk();
};


#endif //PASSPORTREADER_PKCS7PARSER_H
