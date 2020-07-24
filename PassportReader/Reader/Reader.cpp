
#include "Reader.h"
#include "../../Crypto/PassportCrypto.h"
#include "../../Tools/Hexdump.h"
#include "../../Tools/Log.h"
#include "NFC.h"
#include <string.h>

using namespace std;

bool Reader::selectAID() {
    uint8_t capdu[12];
    size_t capdulen = 12;
    uint8_t rapdu[256];
    size_t rapdulen = 256;

    memcpy(capdu, "\x00\xA4\x04\x0C\x07\xA0\x00\x00\x02\x47\x10\x01", 12);

    if (!NFC::transmit(capdu, capdulen, rapdu, &rapdulen))
        return false;
    if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00)
        return false;
    Log(LOG_LEVEL_INFO) << "NFC READER >> Application selected";
    return true;
}

bool Reader::initConnection(BacKeys* bacKeys, SessionKeys *sessionKeys)
{
    if(!selectAID()) {
        Log(LOG_LEVEL_ERROR) << "NFC READER >> Select AID failed";
        return false;
    }

    uint8_t rndic[8];
    if(!getRND(rndic)) {
        Log(LOG_LEVEL_ERROR) << "NFC READER >> Get random seed failed";
        return false;
    }

    if(!getSessionKeys(bacKeys, rndic, sessionKeys)) {
        Log(LOG_LEVEL_ERROR) << "NFC READER >> Get session keys failed";
        return false;
    }

    return true;
}

bool Reader::getRND(uint8_t* rndic) {
    uint8_t capdu[5];
    size_t capdulen = 5;
    uint8_t rapdu[256];
    size_t rapdulen = 100;

    memcpy(capdu, "\x00\x84\x00\x00\x08", 5);

    if (!NFC::transmit(capdu, capdulen, rapdu, &rapdulen)) {
        Log(LOG_LEVEL_ERROR) << "Failed to get RND, transmit failed";
        return false;
    }
    if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) {
        Log(LOG_LEVEL_ERROR) << "Failed to get RND, rapdulen too short or not ending with 9000";
        return false;
    }
    Log(LOG_LEVEL_INFO) << "NFC READER >> Got random seed";

    memcpy(rndic, rapdu, 8);

    return true;
}

bool Reader::doAA(unsigned char* challenge, unsigned char* signature, unsigned int* signatureLength, SessionKeys* sessionKeys) {

    unsigned char command[14];
    memcpy(command, "\x00", 1);
    memcpy(command+1, "\x88", 1);
    memcpy(command+2, "\x00", 1);
    memcpy(command+3, "\x00", 1);
    memcpy(command+4, "\x08", 1);
    memcpy(command+5, challenge, 8);
    memcpy(command+13, "\x00", 1);

    unsigned char rapdu[512];
    size_t rapduLength = 512;

    if (!NFC::transmit((uint8_t*)command, (size_t)14, rapdu, &rapduLength))
        return false;
    if (rapduLength < 2 || rapdu[rapduLength-2] != 0x90 || rapdu[rapduLength-1] != 0x00)
        return false;

    *signatureLength = rapduLength - 2;
    memcpy(signature, rapdu, rapduLength);

    return true;
}

bool Reader::readFile(unsigned char* fileId, unsigned char* file, unsigned int* fileSize, SessionKeys* sessionKeys)
{
    if(!selectFile(fileId, sessionKeys)) {
        Log(LOG_LEVEL_ERROR) << "NFC READER >> Failed to selected file";
        return false;
    }

    unsigned char fileHeader[4];
    if(readFilePart(fileHeader, 0, 4, sessionKeys)) {

        unsigned char asn1Length[3];
        memcpy(asn1Length, fileHeader+1, 3);

        unsigned int fileLength = 0;
        PassportCrypto::asn1ToInt(asn1Length, &fileLength);

        fileLength += 2;
        if(fileHeader[1] == 0x82) {
            fileLength += 2;
        } else if(fileHeader[1] == 0x81) {
            fileLength += 1;
        }

        Log(LOG_LEVEL_INFO) << "NFC READER >> File length: " << fileLength;

        unsigned char fileContent[fileLength];

        unsigned int cursor = 0;
        unsigned int chunkSize = 98;
        while(cursor < fileLength) {

            if(cursor + chunkSize > fileLength) {
                chunkSize = fileLength - cursor;
            }
            unsigned char fileChunk[chunkSize];

            Log(LOG_LEVEL_INFO) << "NFC READER >> Chunk size: " << chunkSize;

            if(readFilePart(fileChunk, cursor, chunkSize, sessionKeys)) {
                memcpy(fileContent + cursor, fileChunk, chunkSize);
            }

            cursor += chunkSize;
        }

        *fileSize = fileLength;
        memcpy(file, fileContent, fileLength);
    }




    return true;
}

bool Reader::readFilePart(unsigned char* content, unsigned int offset, int length, SessionKeys* sessionKeys)
{
    unsigned char commandHeader[4];
    unsigned char paddedCommandHeader[8];
    unsigned char headerOffset[2];
    PassportCrypto::intTo16bitsChar(offset, headerOffset);

    memcpy(commandHeader, "\x0C", 1);
    memcpy(commandHeader+1, "\xB0", 1);
    memcpy(commandHeader+2, headerOffset, 2);

    int paddedCommandHeaderLength;
    PassportCrypto::paddMessage(commandHeader, 4, paddedCommandHeader, &paddedCommandHeaderLength);

    unsigned char do97[3];
    PassportCrypto::buildDO97(length, do97);

    unsigned char m[paddedCommandHeaderLength + 3];

    memcpy(m, paddedCommandHeader, (size_t)paddedCommandHeaderLength);
    memcpy(m + paddedCommandHeaderLength, do97, 3);

    char macKey1[8];
    char macKey2[8];
    sessionKeys->getKMac(macKey1, macKey2);

    sessionKeys->incrementSequenceCounter();
    unsigned char n[3 + paddedCommandHeaderLength + 8];
    char sequenceCounter[8];
    sessionKeys->getSequenceCounter(sequenceCounter);

    memcpy(n, sequenceCounter, 8);
    memcpy(n + 8, m, (size_t)(3 + 8));

    unsigned char mac[8];
    PassportCrypto::calculate3DESMAC(mac, macKey1, macKey2, n, (3 + paddedCommandHeaderLength + 8));

    unsigned char do8e[10];
    int do8eLength;
    PassportCrypto::buildDO8E(mac, do8e, &do8eLength);

    unsigned char commandData[3 + do8eLength];
    memcpy(commandData, do97, (size_t)3);
    memcpy(commandData + 3, do8e, (size_t)do8eLength);

    unsigned char capdu[256];
    int capduLength;
    buildAPDU(commandHeader, 3 + do8eLength, commandData, 0, capdu, &capduLength);
    sessionKeys->incrementSequenceCounter();

    unsigned char rapdu[256];
    size_t rapduLength = 256;

    if (!NFC::transmit((uint8_t*)capdu, (size_t)capduLength, rapdu, &rapduLength))
        return false;
    if (rapduLength < 2 || rapdu[rapduLength-2] != 0x90 || rapdu[rapduLength-1] != 0x00)
        return false;

    char encKey1[8];
    char encKey2[8];
    sessionKeys->getKEnc(encKey1, encKey2);

    unsigned char encryptedResponseAsn1Length[3];
    memcpy(encryptedResponseAsn1Length, rapdu+1, 3);
    unsigned int encryptedResponseLength = 0;
    PassportCrypto::asn1ToInt(encryptedResponseAsn1Length, &encryptedResponseLength);
    encryptedResponseLength -= 1;
    unsigned char encryptedResponse[encryptedResponseLength];

    memcpy(encryptedResponse, rapdu+3, (size_t)encryptedResponseLength);

    unsigned char decryptedContent[encryptedResponseLength];
    PassportCrypto::decryptWith3DES(encryptedResponse, encKey1, encKey2, decryptedContent, encryptedResponseLength);

    unsigned int unPaddedLength = 0;
    PassportCrypto::unpad(decryptedContent, encryptedResponseLength, &unPaddedLength);
    memcpy(content, decryptedContent, unPaddedLength);

    return true;
}

bool Reader::selectFile(unsigned char* fileId, SessionKeys* sessionKeys)
{
    unsigned char commandHeader[4];
    unsigned char paddedCommandHeader[8];
    memcpy(commandHeader, "\x0C", 1);
    memcpy(commandHeader+1, "\xA4", 1);
    memcpy(commandHeader+2, "\x02", 1);
    memcpy(commandHeader+3, "\x0C", 1);

    int paddedCommandHeaderLength;
    PassportCrypto::paddMessage(commandHeader, 4, paddedCommandHeader, &paddedCommandHeaderLength);
    unsigned char paddedCommand[paddedCommandHeaderLength];

    int paddedCommandLength;
    PassportCrypto::paddMessage(fileId, 2, paddedCommand, &paddedCommandLength);

    unsigned char encryptedCommand[paddedCommandLength];
    char encKey1[8];
    char encKey2[8];
    sessionKeys->getKEnc(encKey1, encKey2);

    printf("encKeys:");
    Hexdump::dump(encKey1, 8);
    Hexdump::dump(encKey2, 8);

    PassportCrypto::encryptWith3DES(encryptedCommand, encKey1, encKey2, paddedCommand, 8);

    int do87Length;
    unsigned char do87[32];
    PassportCrypto::buildDO87(encryptedCommand, 8, do87, &do87Length);

    unsigned char m[do87Length + paddedCommandHeaderLength];

    memcpy(m, paddedCommandHeader, (size_t)paddedCommandHeaderLength);
    memcpy(m + paddedCommandHeaderLength, do87, (size_t)do87Length);

    char macKey1[8];
    char macKey2[8];
    sessionKeys->getKMac(macKey1, macKey2);

    sessionKeys->incrementSequenceCounter();
    unsigned char n[do87Length + paddedCommandHeaderLength + 8];
    char sequenceCounter[8];
    sessionKeys->getSequenceCounter(sequenceCounter);

    memcpy(n, sequenceCounter, 8);
    memcpy(n + 8, m, (size_t)(do87Length + 8));

    unsigned char mac[8];
    PassportCrypto::calculate3DESMAC(mac, macKey1, macKey2, n, do87Length + paddedCommandHeaderLength + 8);
    unsigned char do8e[10];
    int do8eLength;
    PassportCrypto::buildDO8E(mac, do8e, &do8eLength);

    unsigned char commandData[do87Length + do8eLength];
    memcpy(commandData, do87, (size_t)do87Length);
    memcpy(commandData + do87Length, do8e, (size_t)do8eLength);

    unsigned char capdu[256];
    int capduLength;
    buildAPDU(commandHeader, do87Length + do8eLength, commandData, 0, capdu, &capduLength);
    sessionKeys->incrementSequenceCounter();

    unsigned char rapdu[256];
    size_t rapduLength = 256;

    if (!NFC::transmit((uint8_t*)capdu, (size_t)capduLength, rapdu, &rapduLength))
        return false;
    if (rapduLength < 2 || rapdu[rapduLength-2] != 0x90 || rapdu[rapduLength-1] != 0x00)
        return false;

    return true;
}

bool Reader::getSessionKeys(BacKeys* bacKeys, uint8_t* rndic, SessionKeys* sessionKeys) {
    char rndifd[8];
    char kifd[16];

    PassportCrypto::generateRandom(rndifd, 8);
    PassportCrypto::generateRandom(kifd, 16);

    unsigned char s[32];

    memcpy(s, rndifd, 8);
    memcpy(s+8, rndic, 8);
    memcpy(s+16, kifd, 16);

    char bacEncKey1[8];
    char bacEncKey2[8];
    bacKeys->getKEnc(bacEncKey1, bacEncKey2);
    unsigned char encryptedMessage[32];

    Log(LOG_LEVEL_INFO) << "s: " << Hexdump::ucharToHexString((unsigned char*)s, 32);

    PassportCrypto::encryptWith3DES(encryptedMessage, bacEncKey1, bacEncKey2, s, 32);

    unsigned char mac[8];

    char bacMacKey1[8];
    char bacMacKey2[8];
    bacKeys->getKMac(bacMacKey1, bacMacKey2);

    PassportCrypto::calculate3DESMAC(mac, bacMacKey1, bacMacKey2, encryptedMessage, 32);

    unsigned char capdu[256];
    int capduLength;

    unsigned char commandData[40];
    memcpy(commandData, &encryptedMessage, 32);
    memcpy(commandData+32, &mac, 8);

    uint8_t rapdu[256];
    size_t rapduLength = 256;

    buildAPDU(0x00, 0x82, 0x00, 0x00, 40, commandData, 40, capdu, &capduLength);

    Hexdump::dump(capdu, capduLength);

    if (!NFC::transmit((uint8_t*)capdu, (size_t)capduLength, rapdu, &rapduLength))
        return false;
    if (rapduLength < 2 || rapdu[rapduLength-2] != 0x90 || rapdu[rapduLength-1] != 0x00)
        return false;

    unsigned char encryptedResponse[32];
    unsigned char decryptedResponse[32];
    memcpy(encryptedResponse, rapdu, 32);

    PassportCrypto::decryptWith3DES(encryptedResponse, bacEncKey1, bacEncKey2, decryptedResponse, 32);

    unsigned char kic[16];
    memcpy(kic, decryptedResponse+16, 16);

    unsigned char kSeed[16];
    char bacKSeed[16];
    char sequenceCounter[8];

    memcpy(sequenceCounter, decryptedResponse+4, 4);
    memcpy(sequenceCounter+4, decryptedResponse+12, 4);

    Log(LOG_LEVEL_INFO) << "sequenceCounter: " << Hexdump::ucharToHexString((unsigned char*)sequenceCounter, 8);

    bacKeys->calculateKSeed(bacKSeed);

    PassportCrypto::calculateXor(kSeed, kic, (unsigned char*) kifd, 16);

    sessionKeys->setSeed(kSeed);
    sessionKeys->setSequenceCounter(sequenceCounter);

    Log(LOG_LEVEL_INFO) << "NFC READER >> Got session keys";

    return true;
}

void Reader::buildAPDU(unsigned char* commandHeader,
               int lc, unsigned char * commandData, int le,
               unsigned char *apdu, int *apduLength
) {
    buildAPDU(commandHeader[0], commandHeader[1], commandHeader[2], commandHeader[3], lc, commandData, le, apdu, apduLength);
}


void Reader::buildAPDU(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
                       int lc, unsigned char *commandData, int le,
                       unsigned char *apdu, int *apduLength
) {

    unsigned char clc;
    clc = (unsigned char)lc;

    unsigned char cle;
    cle = (unsigned char)le;

    memcpy(apdu, &cla, 1);
    memcpy(apdu+1, &ins, 1);
    memcpy(apdu+2, &p1, 1);
    memcpy(apdu+3, &p2, 1);
    memcpy(apdu+4, &clc, 1);
    memcpy(apdu+5, commandData, (size_t)lc);
    memcpy(apdu+5+lc, &cle, 1);

    *apduLength = lc + 6;
}

void Reader::close() {
    NFC::close();
}
