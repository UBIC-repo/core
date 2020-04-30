#ifndef PASSPORTREADER_BACKEYS_H
#define PASSPORTREADER_BACKEYS_H

#include <string>

class BacKeys {

public:
    void calculateKey(int cType, char* ka, char* kb);
    void getKEnc(char* ka, char* kb);
    void getKMac(char* ka, char* kb);
    void calculateKSeed(char* seed);
    char calculateChecksumDigit(std::string digits, int length);

    void setDocumentNumber(std::string nDocumentNumber);
    void setDateOfBirth(std::string nDateOfBirth);
    void setDateOfExpiry(std::string nDateOfExpiry);
    std::string getDocumentNumber();
    std::string getDateOfBirth();
    std::string getDateOfExpiry();

private:
    std::string documentNumber;
    std::string dateOfBirth;
    std::string dateOfExpiry;
};


#endif //PASSPORTREADER_BACKEYS_H
