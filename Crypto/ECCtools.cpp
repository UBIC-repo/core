
#include "ECCtools.h"

std::vector<unsigned char> ECCtools::ecPointToVector(const EC_GROUP* curveParams, const EC_POINT* point) {
    BN_CTX *ctx = BN_CTX_new();
    unsigned char pointChar[1024];
    size_t length = EC_POINT_point2oct(curveParams, point, POINT_CONVERSION_COMPRESSED, pointChar, 1024, ctx);
    BN_CTX_free(ctx);

    std::vector<unsigned char> pointVector(pointChar, pointChar + length);
    return pointVector;
}

EC_POINT* ECCtools::vectorToEcPoint(const EC_GROUP* curveParams, std::vector<unsigned char> pointVector) {
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT* point = EC_POINT_new(curveParams);
    EC_POINT_oct2point(curveParams, point, pointVector.data(), pointVector.size(), ctx);
    BN_CTX_free(ctx);

    return point;
}

std::vector<unsigned char> ECCtools::bnToVector(const BIGNUM* num) {
    unsigned char binNum[512];
    int length = BN_bn2bin(num, binNum);

    std::vector<unsigned char> binVector(binNum, binNum + length);
    return binVector;
}

BIGNUM* ECCtools::vectorToBn(std::vector<unsigned char> numVector) {
    return BN_bin2bn(numVector.data(), (int)numVector.size(), NULL);
}
