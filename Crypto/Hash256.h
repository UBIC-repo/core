
#ifndef TX_HASH256_H
#define TX_HASH256_H


class Hash256 {
public:
    static void hash256(unsigned char* message, unsigned int messageLength, unsigned char* digest);
    static std::vector<unsigned char> hash256(std::vector<unsigned char> message);
};


#endif //TX_HASH256_H
