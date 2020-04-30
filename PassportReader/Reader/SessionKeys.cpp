#include <cstring>
#include "SessionKeys.h"
#include "../../Crypto/PassportCrypto.h"

void SessionKeys::calculateKey(int cType, char* ka, char* kb) {
    char d[100];
    memcpy(d, seed, 16);
    memcpy(d+16, "\0", 1);
    memcpy(d+17, "\0", 1);
    memcpy(d+18, "\0", 1);
    if(cType == 1)
        memcpy(d+19, "\01", 1);
    if(cType == 2)
        memcpy(d+19, "\02", 1);

    char md[20];
    PassportCrypto::sha1(d, 20, md);

    memcpy(ka, md + 0, 8);
    memcpy(kb, md + 8, 8);
}

void SessionKeys::getKEnc(char* ka, char* kb) {
    calculateKey(1, ka, kb);
}

void SessionKeys::getKMac(char* ka, char* kb) {
    calculateKey(2, ka, kb);
}

void SessionKeys::setSeed(unsigned char* seed)
{
    memcpy(this->seed, (char*)seed, 16);
}

void SessionKeys::setSeed(char* seed)
{
    memcpy(this->seed, seed, 16);
}

void SessionKeys::setSequenceCounter(char* sequenceCounter)
{
    memcpy(this->sequenceCounter, sequenceCounter, 8);
}

void SessionKeys::getSequenceCounter(char* sequenceCounter)
{
    memcpy(sequenceCounter, this->sequenceCounter, 8);
}

void SessionKeys::incrementSequenceCounter()
{
    bool doIncrement = true;
    for(int i = 7; i >= 0; i--) {
        if(doIncrement) {
            if(sequenceCounter[i] == (char)0xFF) {
                sequenceCounter[i] = (char)0x00;
            } else {
                unsigned int inc = (unsigned int)sequenceCounter[i];
                sequenceCounter[i] = (char)(inc+1);
                doIncrement = false;
            }
        }
    }
}