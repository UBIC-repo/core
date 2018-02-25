#ifndef PASSPORTREADER_SESSIONKEYS_H
#define PASSPORTREADER_SESSIONKEYS_H

#include <cstdint>
#include "BacKeys.h"

class SessionKeys {
public:
    void calculateKey(int cType, char* ka, char* kb);
    void getKEnc(char* ka, char* kb);
    void getKMac(char* ka, char* kb);
    void setSeed(unsigned char* seed);
    void setSeed(char* seed);
    void setSequenceCounter(char* sequenceCounter);
    void getSequenceCounter(char*sequenceCounter);
    void incrementSequenceCounter();

private:
    char seed[16];
    char sequenceCounter[8];
};


#endif //PASSPORTREADER_SESSIONKEYS_H
