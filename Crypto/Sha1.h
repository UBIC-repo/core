#ifndef UBICD_SHA1_H
#define UBICD_SHA1_H


#include <vector>

class Sha1 {
public:
    static void sha1(unsigned char* message, unsigned int messageLength, unsigned char* digest);
    static std::vector<unsigned char> sha1(std::vector<unsigned char> message);
};


#endif //UBICD_SHA1_H
