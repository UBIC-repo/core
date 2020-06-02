
#include "VectorTool.h"
#include <cstring>

std::vector<unsigned char> VectorTool::concatCharVector(std::vector<unsigned char> elem1, std::vector<unsigned char> elem2) {
    elem1.insert(elem1.end(), elem2.begin(), elem2.end());
    return elem1;
}

std::vector<unsigned char> VectorTool::concatCharVector(std::vector<unsigned char> elem1, const char* elem2) {
    std::vector<unsigned char> np(elem2, elem2 + strlen(elem2));
    elem1.insert(elem1.end(), np.begin(), np.end());
    return elem1;
}

std::vector<unsigned char> VectorTool::concatCharVector(const char* elem1, const char* elem2) {
    std::vector<unsigned char> bp(elem1, elem1 + strlen(elem1));
    std::vector<unsigned char> np(elem2, elem2 + strlen(elem2));

    return concatCharVector(bp, np);
}


std::vector<unsigned char> VectorTool::prepend(unsigned char charElement, int toSize, std::vector<unsigned char> vectorElement) {
    while(vectorElement.size() < toSize) {
        vectorElement.insert(vectorElement.begin(), charElement);
    }

    return vectorElement;
}

std::vector<unsigned char> VectorTool::prependToCorrectSize(std::vector<unsigned char> vectorElement) {
    int vectorSize = (int)vectorElement.size();

    if (vectorSize == 20 ||
        vectorSize == 28 ||
        vectorSize == 32 ||
        vectorSize == 64 ||
        vectorSize == 128 ||
        vectorSize == 256 ||
        vectorSize == 512) {
        return vectorElement;
    }

    if(vectorSize < 20) {
        return prepend((unsigned char)0x00, 20, vectorElement);
    } else if(vectorSize > 20 && vectorSize < 28) {
        return prepend((unsigned char)0x00, 28, vectorElement);
    } else if(vectorSize > 28 && vectorSize < 32) {
        return prepend((unsigned char)0x00, 32, vectorElement);
    } else if(vectorSize > 32 && vectorSize < 64) {
        return prepend((unsigned char)0x00, 64, vectorElement);
    } else if(vectorSize > 64 && vectorSize < 128) {
        return prepend((unsigned char)0x00, 128, vectorElement);
    } else if(vectorSize > 128 && vectorSize < 256) {
        return prepend((unsigned char)0x00, 256, vectorElement);
    } else if(vectorSize > 256 && vectorSize < 512) {
        return prepend((unsigned char)0x00, 512, vectorElement);
    }

    return vectorElement;
}
