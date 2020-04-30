
#ifndef TX_RIPEMD160_H
#define TX_RIPEMD160_H


#include <vector>

class Ripemd160 {
public:
    static void ripemd160(unsigned char* message, unsigned int messageLength, unsigned char* digest);
    static std::vector<unsigned char> ripemd160(std::vector<unsigned char> message);
};


#endif //TX_RIPEMD160_H
