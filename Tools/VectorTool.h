#ifndef UBICD_VECTORTOOL_H
#define UBICD_VECTORTOOL_H

#include <vector>

class VectorTool {
public:
    static std::vector<unsigned char> concatCharVector(std::vector<unsigned char> elem1, std::vector<unsigned char> elem2);
    static std::vector<unsigned char> concatCharVector(std::vector<unsigned char> elem1, const char* elem2);
    static std::vector<unsigned char> concatCharVector(const char* elem1, const char* elem2);
    static std::vector<unsigned char> prepend(unsigned char charElement, int toSize, std::vector<unsigned char> vectorElement);
    static std::vector<unsigned char> prependToCorrectSize(std::vector<unsigned char> vectorElement);
};


#endif //UBICD_VECTORTOOL_H
