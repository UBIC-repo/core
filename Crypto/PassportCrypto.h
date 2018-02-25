#ifndef PASSPORTREADER_CRYPTO_H
#define PASSPORTREADER_CRYPTO_H


#include <openssl/des.h>

class PassportCrypto {
public:
    static void sha1(char* data, int length, char* nMd);
    static void generateRandom(char* random, int length);
    static void encryptWith3DES(unsigned char* encryptedMessage, char* key1, char* key2, unsigned char* message, int messageLength);
    static void decryptWith3DES(unsigned char* encryptedMessage, char* key1, char* key2, unsigned char* message, int messageLength);
    static void calculateXor(unsigned char* res, unsigned char* c1, unsigned char* c2, int length);
    static void calculate3DESMAC(unsigned char* mac, char* key1, char* key2, unsigned char* message, int messageLength);
    static void paddMessage(unsigned char* message, int messageLength, unsigned char* paddedMessage, int* paddedMessageLength);
    static void buildDO87(unsigned char* command, int commandLength, unsigned char* do87, int* do87Length);
    static void buildDO8E(unsigned char* mac, unsigned char* do8e, int* do8eLength);
    static void buildDO97(int length, unsigned char* do97);
    static void asn1ToInt(unsigned char* asn1, unsigned int* intVal);
    static void intToAsn1(unsigned int intVal, unsigned char* asn1, unsigned int* asn1Length);
    static void intTo16bitsChar(unsigned int intVal, unsigned char* intChar);
    static void unpad(unsigned char *padded, unsigned int paddedLength, unsigned int *unPaddedLength);
};


#endif //PASSPORTREADER_CRYPTO_H
