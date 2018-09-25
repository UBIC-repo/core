
#ifndef UBICD_MRZPARSER_H
#define UBICD_MRZPARSER_H


#include "KYCResponseOject.h"

class MRZParser {
private:
    KYCResponseObject parseTD1(std::vector<unsigned char> mrz);
    KYCResponseObject parseTD2(std::vector<unsigned char> mrz);
    KYCResponseObject parseTD3(std::vector<unsigned char> mrz);
public:
    KYCResponseObject parse(std::vector<unsigned char> mrz);
};


#endif //UBICD_MRZPARSER_H
