
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "Ripemd160.h"

void Ripemd160::ripemd160(unsigned char* message, unsigned int messageLength, unsigned char* digest) {
    unsigned int digestLength;
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(mdctx, message, messageLength);
    EVP_DigestFinal_ex(mdctx, digest, &digestLength);

    EVP_MD_CTX_destroy(mdctx);
}

std::vector<unsigned char> Ripemd160::ripemd160(std::vector<unsigned char> message) {
    unsigned char digest[20];
    Ripemd160::ripemd160(message.data(), (unsigned int)message.size(), digest);

    std::vector<unsigned char> digestVector(digest, digest + 20);
    return digestVector;
}
