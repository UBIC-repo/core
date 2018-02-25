
#ifndef PASSPORTREADER_HEXDUMP_H
#define PASSPORTREADER_HEXDUMP_H

#include <string>
#include <vector>

class Hexdump {
public:
    static void dump(unsigned char* toDump, uint16_t dumpSize);
    static void dump(char* toDump, uint16_t dumpSize);
    static std::string vectorToHexString(std::vector<unsigned char> charArray);
    static std::vector<unsigned char> hexStringToVector(std::string hexString);
    static std::vector<unsigned char> vectorToHexVector(std::vector<unsigned char> charArray);
    static std::string ucharToHexString(unsigned char* charArray, uint32_t charArrayLength);
    static std::vector<unsigned char> stringToCharVector(std::string string);
};


#endif //PASSPORTREADER_HEXDUMP_H
