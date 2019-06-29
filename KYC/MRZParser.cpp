
#include "MRZParser.h"
#include "../Tools/Log.h"


std::string MRZParser::rtrim(std::string s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

std::string MRZParser::formatClean(std::string str) {
    std::replace(str.begin(), str.end(), '<', ' ');
    return rtrim(str);
}

MRZResponseObject MRZParser::parseTD1(std::vector<unsigned char> mrz) {
    MRZResponseObject kycResponseObject;

    uint8_t cursor = 2; //skip Document code
    kycResponseObject.setIso2CountryCode(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 3)));
    cursor += 3; //skip Issuing State or organization

    kycResponseObject.setPassportNumber(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 9)));
    cursor++; //skip check digit
    cursor += 15; //skip optional parameters

    kycResponseObject.setDateOfBirth(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 6)));
    cursor += 6; //skip date of birth
    cursor++; //skip check digit

    kycResponseObject.setGender(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 1)));
    cursor++; //skip gender

    kycResponseObject.setDateOfExpiry(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 6)));
    cursor += 6; //skip date of expiry
    cursor++; //skip check digit

    cursor += 3; //skip nationality
    cursor += 11; //skip Optional data elements
    cursor++; //skipcComposite check digit

    kycResponseObject.setName(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 30)));
    cursor += 30; //skip name

    kycResponseObject.setSuccess(true);
    return kycResponseObject;
}

MRZResponseObject MRZParser::parseTD2(std::vector<unsigned char> mrz) {
    MRZResponseObject kycResponseObject;

    uint8_t cursor = 2; //skip Document code
    kycResponseObject.setIso2CountryCode(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 3)));
    cursor += 3; //skip Issuing State or organization

    kycResponseObject.setName(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 31)));
    cursor += 31; //skip name

    kycResponseObject.setPassportNumber(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 9)));
    cursor += 9; //skip passport number
    cursor++; //skip check digit
    cursor += 3; //skip nationality

    kycResponseObject.setDateOfBirth(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 6)));
    cursor += 6; //skip date of birth
    cursor++; //skip check digit

    kycResponseObject.setGender(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 1)));
    cursor++; //skip gender

    kycResponseObject.setDateOfExpiry(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 6)));
    cursor += 6; //skip date of expiry
    cursor++; //skip check digit

    //ignore the rest

    kycResponseObject.setSuccess(true);
    return kycResponseObject;
}

MRZResponseObject MRZParser::parseTD3(std::vector<unsigned char> mrz) {
    MRZResponseObject kycResponseObject;

    uint8_t cursor = 2; //skip Document code
    kycResponseObject.setIso2CountryCode(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 3)));
    cursor += 3; //skip Issuing State or organization

    kycResponseObject.setName(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 39)));
    cursor += 39; //skip name

    kycResponseObject.setPassportNumber(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 9)));
    cursor += 9; //skip passport number
    cursor++; //skip check digit
    cursor += 3; //skip nationality

    kycResponseObject.setDateOfBirth(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 6)));
    cursor += 6; //skip date of birth
    cursor++; //skip check digit

    kycResponseObject.setGender(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 1)));
    cursor++; //skip gender

    kycResponseObject.setDateOfExpiry(formatClean(std::string(mrz.data() + cursor, mrz.data() + cursor + 6)));
    cursor += 6; //skip date of expiry
    cursor++; //skip check digit

    //ignore the rest

    kycResponseObject.setSuccess(true);
    return kycResponseObject;
}

MRZResponseObject MRZParser::parse(std::vector<unsigned char> mrz) {
    if (mrz.size() == 72) {
        return MRZParser::parseTD3(mrz);
    } else if (mrz.size() == 90) {
        return MRZParser::parseTD1(mrz);
    } else if (mrz.size() == 88) {
        return MRZParser::parseTD3(mrz);
    }

    MRZResponseObject kycResponseObject;
    kycResponseObject.setSuccess(false);

    return kycResponseObject;
}
