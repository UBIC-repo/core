
#include "MRZParser.h"

MRZResponseObject MRZParser::parseTD1(std::vector<unsigned char> mrz) {
    MRZResponseObject kycResponseObject;

    uint8_t cursor = 2; //skip Document code
    kycResponseObject.setIso2CountryCode(std::string(mrz.data() + cursor, mrz.data() + cursor + 3));
    cursor += 3; //skip Issuing State or organization

    kycResponseObject.setPassportNumber(std::string(mrz.data() + cursor, mrz.data() + cursor + 9));
    cursor++; //skip check digit
    cursor += 15; //skip optional parameters

    kycResponseObject.setDateOfBirth(std::string(mrz.data() + cursor, mrz.data() + cursor + 6));
    cursor += 6; //skip date of birth
    cursor++; //skip check digit

    kycResponseObject.setGender(std::string(mrz.data() + cursor, mrz.data() + cursor + 1));
    cursor++; //skip gender

    kycResponseObject.setDateOfExpiry(std::string(mrz.data() + cursor, mrz.data() + cursor + 6));
    cursor += 6; //skip date of expiry
    cursor++; //skip check digit

    cursor += 3; //skip nationality
    cursor += 11; //skip Optional data elements
    cursor++; //skipcComposite check digit

    kycResponseObject.setName(std::string(mrz.data() + cursor, mrz.data() + cursor + 30));
    cursor += 30; //skip name
}

MRZResponseObject MRZParser::parseTD2(std::vector<unsigned char> mrz) {
    MRZResponseObject kycResponseObject;

    uint8_t cursor = 2; //skip Document code
    kycResponseObject.setIso2CountryCode(std::string(mrz.data() + cursor, mrz.data() + cursor + 3));
    cursor += 3; //skip Issuing State or organization

    kycResponseObject.setName(std::string(mrz.data() + cursor, mrz.data() + cursor + 31));
    cursor += 31; //skip name

    kycResponseObject.setPassportNumber(std::string(mrz.data() + cursor, mrz.data() + cursor + 9));
    cursor += 9; //skip name
    cursor++; //skip check digit
    cursor += 3; //skip nationality

    kycResponseObject.setDateOfBirth(std::string(mrz.data() + cursor, mrz.data() + cursor + 6));
    cursor += 6; //skip date of birth
    cursor++; //skip check digit

    kycResponseObject.setGender(std::string(mrz.data() + cursor, mrz.data() + cursor + 1));
    cursor++; //skip gender

    kycResponseObject.setDateOfExpiry(std::string(mrz.data() + cursor, mrz.data() + cursor + 6));
    cursor += 6; //skip date of expiry
    cursor++; //skip check digit

    //ignore the rest
}

MRZResponseObject MRZParser::parseTD3(std::vector<unsigned char> mrz) {

}

MRZResponseObject MRZParser::parse(std::vector<unsigned char> mrz) {

}
