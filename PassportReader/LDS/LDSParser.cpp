#include <cstring>
#include "LDSParser.h"
#include "../../Crypto/PassportCrypto.h"

LDSParser::LDSParser(unsigned char *lds, unsigned int ldsLength)
{
    memcpy(this->lds, lds, ldsLength);
    this->ldsLength = ldsLength;
}

LDSParser* LDSParser::getTag(unsigned char *tag)
{
    int tagLength = 1;

    if(tag[0] == 0x7F || tag[0] == 0x5F) {
        tagLength = 2;
    }

    unsigned int cursor = 0;
    unsigned char currentTag[2];

    while(cursor < this->ldsLength) {

        if(this->lds[cursor] == 0x7F || this->lds[cursor] == 0x5F) {
            memcpy(currentTag, this->lds + cursor, 2);
            cursor += 2;
        } else {
            memcpy(currentTag, this->lds + cursor, 1);
            cursor += 1;
        }

        unsigned int currentTagContentLength = 0;
        unsigned char currentTagContentAsn1Length[3];
        memcpy(currentTagContentAsn1Length, this->lds + cursor, 3);

        PassportCrypto::asn1ToInt(currentTagContentAsn1Length, &currentTagContentLength);

        cursor += 1;
        if(currentTagContentAsn1Length[0] == 0x82) {
            cursor += 2;
        } else if(currentTagContentAsn1Length[0] == 0x81){
            cursor += 1;
        }

        if((currentTag[0] != 0x7F && currentTag[0] != 0x5F && currentTag[0] == tag[0])
           || (tag[0] == currentTag[0] && tag[1] == currentTag[1])
        ) {
            unsigned char currentTagContent[currentTagContentLength];
            memcpy(currentTagContent, this->lds + cursor, currentTagContentLength);

            return new LDSParser(currentTagContent, currentTagContentLength);
        }

        cursor += currentTagContentLength;
    }

    return nullptr;
}

void LDSParser::getContent(unsigned char *lds, unsigned int *ldsLength)
{
    memcpy(lds, this->lds, this->ldsLength);
    *ldsLength = this->ldsLength;
}