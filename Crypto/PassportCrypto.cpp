#include "PassportCrypto.h"
#include "openssl/sha.h"
#include <openssl/rand.h>
#include <cstring>
#include <stdio.h>
#include "../Tools/Hexdump.h"

void PassportCrypto::sha1(char* data, int length, char* nMd) {
    SHA_CTX c;
    unsigned char md[20];

    SHA1_Init(&c);
    SHA1_Update(&c, data, static_cast<size_t>(length));
    SHA1_Final(md, &c);

    printf("\ndata:");
    Hexdump::dump(data, length);

    printf("hash:");
    Hexdump::dump(md, 20);

    sprintf(nMd, (char*)md);
    Hexdump::dump(nMd, 20);
}

void PassportCrypto::generateRandom(char* random, int length) {
    RAND_bytes((unsigned char*)random, length);
}

void PassportCrypto::encryptWith3DES(unsigned char* encryptedMessage, char* key1, char* key2, unsigned char* message, int messageLength) {

    DES_key_schedule ks1;
    DES_set_key_unchecked((const_DES_cblock*) key1, &ks1);

    DES_key_schedule ks2;
    DES_set_key_unchecked((const_DES_cblock*) key2, &ks2);

    DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DES_ede2_cbc_encrypt(message, encryptedMessage, (long) messageLength, &ks1, &ks2, &iv, DES_ENCRYPT);
}

void PassportCrypto::decryptWith3DES(unsigned char* encryptedMessage, char* key1, char* key2, unsigned char* message, int messageLength) {

    DES_key_schedule ks1;
    DES_set_key_unchecked((const_DES_cblock*) key1, &ks1);

    DES_key_schedule ks2;
    DES_set_key_unchecked((const_DES_cblock*) key2, &ks2);

    DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DES_ede2_cbc_encrypt(encryptedMessage, message, (long) messageLength, &ks1, &ks2, &iv, DES_DECRYPT);
}

void PassportCrypto::calculateXor(unsigned char* res, unsigned char* c1, unsigned char* c2, int length) {
    for(int i = 0; i < length; i++) {
        res[i] = c1[i] ^ c2[i];
    }
}

void PassportCrypto::paddMessage(unsigned char* message, int messageLength, unsigned char* paddedMessage, int* paddedMessageLength)
{
    *paddedMessageLength = messageLength + 1;

    if((*paddedMessageLength % 8)) {
        *paddedMessageLength += 8 - (*paddedMessageLength % 8);
    }

    memcpy(paddedMessage, message, (size_t)messageLength);
    memcpy(paddedMessage+messageLength, "\x80", 1);

    for(int i = 1; i + 1 + messageLength <= *paddedMessageLength; i++) {
        memcpy(paddedMessage+(messageLength+i), "\x00", 1);
    }
}

void PassportCrypto::calculate3DESMAC(unsigned char* mac, char* key1, char* key2, unsigned char* message, int messageLength) {

    DES_key_schedule ks1;
    DES_set_key_unchecked((const_DES_cblock*) key1, &ks1);

    DES_key_schedule ks2;
    DES_set_key_unchecked((const_DES_cblock*) key2, &ks2);

    DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    int paddedMessageLength;
    unsigned char paddedMessage[256];

    paddMessage(message, messageLength, paddedMessage, &paddedMessageLength);

    DES_cbc_encrypt(paddedMessage, mac, 8, &ks1, &iv, DES_ENCRYPT);

    unsigned char xorBuffer[8];

    for(int i = 8; i < paddedMessageLength; i+=8) {
        memcpy(xorBuffer, paddedMessage + i, 8);
        calculateXor(mac, mac, xorBuffer, 8);
        DES_cbc_encrypt(mac, mac, 8, &ks1, &iv, DES_ENCRYPT);
        memcpy(mac, mac, 8);
    }

    DES_cbc_encrypt(mac, mac, 8, &ks2, &iv, DES_DECRYPT);
    DES_cbc_encrypt(mac, mac, 8, &ks1, &iv, DES_ENCRYPT);
}

void PassportCrypto::buildDO87(unsigned char* command, int commandLength, unsigned char* do87, int* do87Length)
{
    *do87Length = commandLength + 2;

    unsigned int lengthOfLength;
    unsigned char DOLength[4];
    intToAsn1((unsigned int)(commandLength + 1), DOLength, &lengthOfLength);
    *do87Length += lengthOfLength;

    memcpy(do87, "\x87", 1);
    memcpy(do87 + 1, DOLength, (size_t)lengthOfLength);
    memcpy(do87 + 1 + lengthOfLength, "\x01", 1);
    memcpy(do87 + 2 + lengthOfLength, command, (size_t)commandLength);
}

void PassportCrypto::buildDO8E(unsigned char* mac, unsigned char* do8e, int* do8eLength)
{
    *do8eLength = 10;
    memcpy(do8e, "\x8E", 1);
    memcpy(do8e + 1, "\x08", 1);
    memcpy(do8e + 2, mac, 8);
}

void PassportCrypto::buildDO97(int length, unsigned char* do97)
{
    memcpy(do97, "\x97", 1);
    memcpy(do97 + 1, "\x01", 1);
    memcpy(do97 + 2, (char*) &length, 1);
}

void PassportCrypto::asn1ToInt(unsigned char* asn1, unsigned int* intVal)
{
    if(asn1[0] == 0x82) {
        *intVal =  ((unsigned int)asn1[1] << 8) + (unsigned int)asn1[2];
    } else if(asn1[0] == 0x81){
        *intVal = (unsigned int)asn1[1];
    } else {
        *intVal = (unsigned int)asn1[0];
    }
}

void PassportCrypto::intToAsn1(unsigned int intVal, unsigned char* asn1, unsigned int* asn1Length)
{
    if(intVal <= (unsigned int)0x7F) {
        *asn1Length = 1;
        asn1[0] = (unsigned char)intVal;
    } else if(intVal <= (unsigned int)0xFF) {
        *asn1Length = 2;
        asn1[0] = 0x81;
        asn1[1] = (unsigned char)intVal;
    } else if(intVal <= (unsigned int)0xFFFF) {
        *asn1Length = 3;
        asn1[0] = 0x82;
        asn1[1] = (unsigned char)((intVal >> 8) & 0xFF);
        asn1[2] = (unsigned char)(intVal & 0xFF);
    }
}

void PassportCrypto::intTo16bitsChar(unsigned int intVal, unsigned char* intChar)
{
    intChar[0] = (unsigned char)((intVal >> 8) & 0xFF);
    intChar[1] = (unsigned char)(intVal & 0xFF);
}

void PassportCrypto::unpad(unsigned char *padded, unsigned int paddedLength, unsigned int *unPaddedLength)
{
    *unPaddedLength = paddedLength;
    while(padded[*unPaddedLength] != 0x80) {
        (*unPaddedLength)--;
    }
}
