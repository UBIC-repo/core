#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <vector>
#include "Sha1.h"

void Sha1::sha1(unsigned char* message, unsigned int messageLength, unsigned char* digest) {
    unsigned int digestLength;
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(mdctx, message, messageLength);
    EVP_DigestFinal_ex(mdctx, digest, &digestLength);

    EVP_MD_CTX_destroy(mdctx);
}

std::vector<unsigned char> Sha1::sha1(std::vector<unsigned char> message) {
    unsigned char digest[20];
    Sha1::sha1(message.data(), (unsigned int)message.size(), digest);

    std::vector<unsigned char> digestVector(digest, digest + 20);
    return digestVector;
}
