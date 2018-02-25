
#include "Hash160.h"
#include "Ripemd160.h"
#include "Sha256.h"

void Hash160::hash160(unsigned char *message, unsigned int messageLength, unsigned char *digest) {
    Sha256::sha256(message, messageLength, digest);
    Ripemd160::ripemd160(digest, 32, digest);
}

std::vector<unsigned char> Hash160::hash160(std::vector<unsigned char> message) {
    std::vector<unsigned char> sha256 = Sha256::sha256(message);
    std::vector<unsigned char> ripemd160 = Ripemd160::ripemd160(sha256);

    return ripemd160;
}