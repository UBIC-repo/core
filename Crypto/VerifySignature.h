
#ifndef CERTSTORE_VERIFYSIGNATURE_H
#define CERTSTORE_VERIFYSIGNATURE_H


#include <vector>

class VerifySignature {
public:
    static bool verify(unsigned char* msg, size_t mlen, unsigned char* sig, size_t slen, EVP_PKEY* pkey);
    static bool verify(std::vector<unsigned char> msg, std::vector<unsigned char> signature, EVP_PKEY* pkey);
    static bool verify(std::vector<unsigned char> msg, std::vector<unsigned char> signature, std::vector<unsigned char> pubKey);
};


#endif //CERTSTORE_VERIFYSIGNATURE_H
