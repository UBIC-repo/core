
#ifndef TX_HASH160_H
#define TX_HASH160_H


#include <vector>

class Hash160 {
public:
    static void hash160(unsigned char* message, unsigned int messageLength, unsigned char* digest);
    static std::vector<unsigned char> hash160(std::vector<unsigned char> message);
};


#endif //TX_HASH160_H
