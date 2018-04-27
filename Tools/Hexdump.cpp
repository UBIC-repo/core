
#include <ios>
#include <sstream>
#include "Hexdump.h"
#include "stdio.h"

void Hexdump::dump(unsigned char* toDump, uint16_t dumpSize) {
    for(int i = 0; i< dumpSize; i++) {
        printf("%.2X ", toDump[i]);
    }
    printf("\n");
}

void Hexdump::dump(char* toDump, uint16_t dumpSize) {
    Hexdump::dump((unsigned char*)toDump, dumpSize);
}

std::string Hexdump::vectorToHexString(std::vector<unsigned char> charArray) {
    return Hexdump::ucharToHexString(charArray.data(), (uint32_t)charArray.size());
}

std::vector<unsigned char> Hexdump::hexStringToVector(std::string hexString) {
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::vector<unsigned char> s;
    for (uint32_t i = 0; i < hexString.size(); ++i) {
        uint32_t e1 = 0 , e2 = 0;
        for(uint32_t v1 = 0; v1 < 16; v1++) {
            if(hexString.at(i) == hexmap[v1]) {
                e1 = v1;
            }
        }
        i++;
        for(uint32_t v2 = 0; v2 < 16; v2++) {
            if(hexString.at(i) == hexmap[v2]) {
                e2 = v2;
            }
        }

        s.insert(s.begin() + (i/2), (unsigned char)(e1*16 + e2));
    }

    return s;
}

std::vector<unsigned char> Hexdump::vectorToHexVector(std::vector<unsigned char> charArray) {
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::vector<unsigned char> s;
    for (int i = 0; i < charArray.size(); ++i) {
        s.insert(s.begin()+ 2 * i, (unsigned char)hexmap[(charArray.at(i) & 0xF0) >> 4]);
        s.insert(s.begin()+ 2 * i + 1, (unsigned char)hexmap[charArray.at(i) & 0x0F]);
    }

    return s;
}

std::string Hexdump::ucharToHexString(unsigned char* charArray, uint32_t charArrayLength) {
    
    if(charArray == nullptr) {
        return "nullptr";
    }

    if(charArrayLength > 65536) {
        return "charArrayLength overflow";
    }
    
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string s(charArrayLength * 2, ' ');
    for (int i = 0; i < charArrayLength; ++i) {
        s[2 * i] = hexmap[(charArray[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[charArray[i] & 0x0F];
    }
    return s;
}

std::vector<unsigned char> Hexdump::stringToCharVector(std::string string) {
    std::istringstream hex_chars_stream(string);
    std::vector<unsigned char> bytes;

    unsigned char c;
    while (hex_chars_stream >> std::hex >> c)
    {
        bytes.emplace_back(c);
    }

    return bytes;
}
