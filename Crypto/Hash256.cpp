
#include <vector>
#include "Hash256.h"
#include "Sha256.h"

std::vector<unsigned char> Hash256::hash256(std::vector<unsigned char> message) {
    std::vector<unsigned char> sha256 = Sha256::sha256(message);

    return sha256;
}
