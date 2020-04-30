#include "BacKeys.h"
#include "../../Crypto/PassportCrypto.h"
#include "../../Tools/Hexdump.h"
#include "../../Tools/Log.h"
#include <string.h>
#include <iostream>

using namespace std;

void BacKeys::calculateKey(int cType, char* ka, char* kb) {
    char d[100];
    char seed[16];
    calculateKSeed(seed);
    Hexdump::dump(seed, 16);
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

void BacKeys::getKEnc(char* ka, char* kb) {
    calculateKey(1, ka, kb);
}

void BacKeys::getKMac(char* ka, char* kb) {
    calculateKey(2, ka, kb);
}

void BacKeys::calculateKSeed(char* seed) {
    char mrzInfo[100];
    char documentNumberCS = calculateChecksumDigit(documentNumber, 9);
    char dateOfBirthCS = calculateChecksumDigit(dateOfBirth, 6);
    char dateOfExpiryCS = calculateChecksumDigit(dateOfExpiry, 6);

    cout << "documentNumber:";
    cout << documentNumber << "\n";

    cout << "documentNumberCS:";
    cout << documentNumberCS << "\n";

    cout << "dateOfBirth:";
    cout << dateOfBirth << "\n";

    cout << "dateOfBirthCS:";
    cout << dateOfBirthCS << "\n";

    cout << "dateOfExpiry:";
    cout << dateOfExpiry << "\n";

    cout << "dateOfExpiryCS:";
    cout << dateOfExpiryCS << "\n";

    memcpy(mrzInfo, documentNumber.c_str(), 9);
    memcpy(mrzInfo + 9, &documentNumberCS, 1);
    memcpy(mrzInfo + 10, dateOfBirth.c_str(), 6);
    memcpy(mrzInfo + 16, &dateOfBirthCS, 1);
    memcpy(mrzInfo + 17, dateOfExpiry.c_str(), 6);
    memcpy(mrzInfo + 23, &dateOfExpiryCS, 1);
    memcpy(mrzInfo + 24, "\0", 1);

    Log(LOG_LEVEL_INFO) << "mrzInfo: " << mrzInfo;

    char md[20];
    PassportCrypto::sha1(mrzInfo, 24, md);

    memcpy(seed, md, 16);
    Hexdump::dump(seed, 16);
}

char BacKeys::calculateChecksumDigit(std::string digits, int length) {
    int sum = 0;
    int weight = 0;
    for(int i = 0; i < length; i++) {
        int value = 0;

        if(digits[i] > 64 && digits[i] < 91) {
            value = digits[i] - 65 + 10;
        }

        if(digits[i] > 47 && digits[i] < 58) {
            value = digits[i] - 48;
        }

        switch (i%3) {
            case 0:
                weight = 7;
                break;
            case 1:
                weight = 3;
                break;
            case 2:
                weight = 1;
                break;
            default:
                weight = 0;
        }

        sum += weight * value;
    }

    return (char) ((sum %10) + 48);
}

void BacKeys::setDocumentNumber(std::string nDocumentNumber) {
    documentNumber = nDocumentNumber;
}

void BacKeys::setDateOfBirth(std::string nDateOfBirth) {
    dateOfBirth = nDateOfBirth;
}

void BacKeys::setDateOfExpiry(std::string nDateOfExpiry) {
    dateOfExpiry = nDateOfExpiry;
}

std::string BacKeys::getDocumentNumber() {
    return documentNumber;
}

std::string BacKeys::getDateOfBirth() {
    return dateOfBirth;
}

std::string BacKeys::getDateOfExpiry() {
    return dateOfExpiry;
}