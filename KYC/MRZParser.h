
#ifndef UBICD_MRZPARSER_H
#define UBICD_MRZPARSER_H


#include <vector>
#include "MRZResponseObject.h"

class MRZParser {
private:
    std::string rtrim(std::string s);
    std::string formatClean(std::string str);
    MRZResponseObject parseTD1(std::vector<unsigned char> mrz);
    MRZResponseObject parseTD2(std::vector<unsigned char> mrz);
    MRZResponseObject parseTD3(std::vector<unsigned char> mrz);
public:
    MRZResponseObject parse(std::vector<unsigned char> mrz);
};


#endif //UBICD_MRZPARSER_H
