
#include <vector>
#include "Hash256.h"
#include "Sha256.h"

void Hash256::hash256(unsigned char *message, unsigned int messageLength, unsigned char *digest) {
    Sha256::sha256(message, messageLength, digest);
    Sha256::sha256(digest, 32, digest);
}

std::vector<unsigned char> Hash256::hash256(std::vector<unsigned char> message) {
    std::vector<unsigned char> sha256 = Sha256::sha256(message);
    sha256 = Sha256::sha256(message);

    return sha256;
}