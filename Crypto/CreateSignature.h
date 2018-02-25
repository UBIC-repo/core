
#ifndef CERTSTORE_CREATESIGNATURE_H
#define CERTSTORE_CREATESIGNATURE_H


#include <vector>

class CreateSignature {
public:
    static bool sign(EVP_PKEY* key, const unsigned char* message, size_t messageLength, unsigned char* signature, size_t* signatureLength);
    static std::vector<unsigned char> sign(EVP_PKEY* key, std::vector<unsigned char> message);
    static std::vector<unsigned char> sign(std::vector<unsigned char> privateKey, std::vector<unsigned char> message);
};


#endif //CERTSTORE_CREATESIGNATURE_H
