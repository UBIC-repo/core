
#ifndef UBICD_ISO19794PARSER_H
#define UBICD_ISO19794PARSER_H


#include <vector>

class Iso19794Parser {
private:
    std::vector<unsigned char> payload;
public:
    Iso19794Parser(std::vector<unsigned char> payload);
    std::vector<unsigned char> getImage();
};


#endif //UBICD_ISO19794PARSER_H
