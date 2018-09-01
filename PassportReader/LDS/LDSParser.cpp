#include <cstring>
#include <malloc.h>
#include "LDSParser.h"
#include "../../Crypto/PassportCrypto.h"


LDSParser::LDSParser(std::vector<unsigned char> lds)
{
    memcpy(this->lds, lds.data(), lds.size());
    this->ldsLength = (unsigned int)lds.size();
}

LDSParser::LDSParser(unsigned char *lds, unsigned int ldsLength)
{
    memcpy(this->lds, lds, ldsLength);
    this->ldsLength = ldsLength;
}

std::vector<LDSParser> LDSParser::getSequence() {
    unsigned int cursor = 0;

    if(this->lds[cursor] != 0x30 && this->lds[cursor] != 0x31) {
        // isn't a sequence
        return std::vector<LDSParser>();
    }
    cursor++; //skip tag

    unsigned int currentTagContentLength = 0;
    unsigned char currentTagContentAsn1Length[3];
    memcpy(currentTagContentAsn1Length, this->lds + cursor, 3);
    PassportCrypto::asn1ToInt(currentTagContentAsn1Length, &currentTagContentLength);

    cursor++;
    if(currentTagContentAsn1Length[0] == 0x82) {
        cursor += 2;
    } else if(currentTagContentAsn1Length[0] == 0x81){
        cursor += 1;
    }


    int sequenceEnd = cursor + currentTagContentLength;

    std::vector<LDSParser> sequence;

    while(cursor < sequenceEnd) {
        int cursorSeqStart = cursor;
        cursor++; //skip tag
        memcpy(currentTagContentAsn1Length, this->lds + cursor, 3);
        PassportCrypto::asn1ToInt(currentTagContentAsn1Length, &currentTagContentLength);

        cursor++;
        if(currentTagContentAsn1Length[0] == 0x82) {
            cursor += 2;
        } else if(currentTagContentAsn1Length[0] == 0x81){
            cursor += 1;
        }


        sequence.push_back(*(new LDSParser(std::vector<unsigned char>(this->lds + cursorSeqStart, this->lds + cursor + currentTagContentLength))));

        cursor += currentTagContentLength;
    }

    return sequence;
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
            auto currentTagContent = (unsigned char*)malloc(currentTagContentLength);
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

std::vector<unsigned char> LDSParser::getContent()
{
    return std::vector<unsigned char>(this->lds, this->lds + this->ldsLength);
}
