
#include "Iso19794Parser.h"

Iso19794Parser::Iso19794Parser(std::vector<unsigned char> payload) {
    this->payload = payload;
}

std::vector<unsigned char> Iso19794Parser::getImage() {
    int cursor = 0;

    /**
     * Facial record header
     */
    cursor += 4; //skip Format Identifier
    cursor += 4; //skip Version Number

    cursor += 4; //skip Length of Record
    cursor += 2; //skip number of facial images

    /**
     * Facial record data
     */
    cursor += 4; //skip Facial Record Data Length

    if(cursor > this->payload.size()) { return std::vector<unsigned char>(); }

    int numberOfFeaturePoints = ((unsigned int)this->payload[cursor] << 8) + (unsigned int)this->payload[cursor+1];
    cursor += 2;

    cursor += 1; //skip Gender
    cursor += 1; //skip Eye Colour
    cursor += 1; //skip Hair Colour
    cursor += 3; //skip Property Mask
    cursor += 2; //skip Expression
    cursor += 3; //skip Pose Angle
    cursor += 3; //skip Pose Angle Uncertainty

    /**
     * Feature point(s)
     */
    for (int i = 0; i < numberOfFeaturePoints; i++) {
        cursor += 8; //skip Feature Point
    }

    /**
     * Image Information
     */
    cursor += 1; //skip Face Image Type
    cursor += 1; //skip Image Data Type
    cursor += 2; //skip Width
    cursor += 2; //skip Height
    cursor += 1; //skip Image Colour Space
    cursor += 1; //skip Source Type
    cursor += 2; //skip Device Type
    cursor += 2; //skip Quality

    if(cursor > this->payload.size()) { return std::vector<unsigned char>(); }

    return std::vector<unsigned char>(this->payload.begin() + cursor, this->payload.end());
}