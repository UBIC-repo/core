/**
 *
 * The LDS (Logical Data Structure) is an ASN1 like format used to store information on the ePassport
 * See Doc 9303 Part 10 to learn more
 *
 */

#ifndef PASSPORTREADER_LDSPARSER_H
#define PASSPORTREADER_LDSPARSER_H

#include <vector>

class LDSParser {
private:
    unsigned char lds[64000];
    unsigned int ldsLength;
public:
    LDSParser(std::vector<unsigned char> lds);
    LDSParser(unsigned char *lds, unsigned int ldsLength);
    std::vector<LDSParser> getSequence();
    LDSParser* getTag(unsigned char *tag);
    void getContent(unsigned char *lds, unsigned int *ldsLength);
    std::vector<unsigned char> getContent();

    ~LDSParser()
    {
        //free(lds);
    }
};


#endif //PASSPORTREADER_LDSPARSER_H
