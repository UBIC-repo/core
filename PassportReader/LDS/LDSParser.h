/**
 *
 * The LDS (Logical Data Structure) is an ASN1 like format used to store information on the ePassport
 * See Doc 9303 Part 10 to learn more
 *
 */

#ifndef PASSPORTREADER_LDSPARSER_H
#define PASSPORTREADER_LDSPARSER_H

class LDSParser {
private:
    unsigned char lds[64000];
    unsigned int ldsLength;
public:
    LDSParser(unsigned char *lds, unsigned int ldsLength);
    LDSParser* getTag(unsigned char *tag);
    void getContent(unsigned char *lds, unsigned int *ldsLength);
};


#endif //PASSPORTREADER_LDSPARSER_H
