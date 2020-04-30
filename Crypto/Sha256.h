
#ifndef CERTSTORE_SHA256_H
#define CERTSTORE_SHA256_H


class Sha256 {
public:
    static void sha256(unsigned char* message, unsigned int messageLength, unsigned char* digest);
    static std::vector<unsigned char> sha256(std::vector<unsigned char> message);
};


#endif //CERTSTORE_SHA256_H
