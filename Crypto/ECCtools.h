
#ifndef TX_ECCTOOLS_H
#define TX_ECCTOOLS_H


#include <vector>
#include <openssl/ec.h>

class ECCtools {
public:
    static std::vector<unsigned char> ecPointToVector(const EC_GROUP* curveParams, const EC_POINT* point);
    static EC_POINT* vectorToEcPoint(const EC_GROUP* curveParams, std::vector<unsigned char> pointVector);
    static std::vector<unsigned char> bnToVector(const BIGNUM* num);
    static BIGNUM* vectorToBn(std::vector<unsigned char> numVector);
};


#endif //TX_ECCTOOLS_H
