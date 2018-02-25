#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <vector>
#include "Sha256.h"

void Sha256::sha256(unsigned char* message, unsigned int messageLength, unsigned char* digest) {
    unsigned int digestLength;
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, message, messageLength);
    EVP_DigestFinal_ex(mdctx, digest, &digestLength);

    EVP_MD_CTX_destroy(mdctx);
}

std::vector<unsigned char> Sha256::sha256(std::vector<unsigned char> message) {
    unsigned char digest[32];
    Sha256::sha256(message.data(), (unsigned int)message.size(), digest);

    std::vector<unsigned char> digestVector(digest, digest + 32);
    return digestVector;
}
