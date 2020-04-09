
#ifndef TX_TEST_H
#define TX_TEST_H


#include "../BlockHeader.h"

class Test {
public:
    static void importCACerts();
    static void importDSCCerts();
    static void createRootCert();
    static void createValidators();
    static X509* create509(const unsigned char* c, const unsigned char* cn1, const unsigned char* cn2, X509* signer, EVP_PKEY *signerPkey, std::vector<unsigned char> privateKeyVector);
    static void sanitizeUbicFolder();
};


#endif //TX_TEST_H
