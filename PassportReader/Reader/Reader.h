
#include <iostream>
#include "BacKeys.h"
#include "SessionKeys.h"

#ifndef PASSPORTREADER_READER_H
#define PASSPORTREADER_READER_H


class Reader {
public:
    bool selectAID();
    bool initConnection(BacKeys* bacKeys, SessionKeys *sessionKeys);
    bool getRND(uint8_t* rndic);
    bool getSessionKeys(BacKeys* bacKeys, uint8_t* rndic, SessionKeys* sessionKeys);
    bool doAA(unsigned char* challenge, unsigned char* signature, unsigned int* signatureLength, SessionKeys* sessionKeys);
    bool readFile(unsigned char* fileId, unsigned char* file, unsigned int* fileSize, SessionKeys* sessionKeys);
    bool readFilePart(unsigned char* content, unsigned int offset, int length, SessionKeys* sessionKeys);
    bool selectFile(unsigned char* fileId, SessionKeys* sessionKeys);
    void buildAPDU(unsigned char* commandHeader,
                   int lc, unsigned char * commandData, int le,
                   unsigned char *apdu, int *apduLength
    );
    void buildAPDU(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
                   int lc, unsigned char * commandData, int le,
                   unsigned char *apdu, int *apduLength
    );
    void close();
};


#endif //PASSPORTREADER_READER_H
