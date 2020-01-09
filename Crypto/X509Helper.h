
#ifndef UBICD_X509HELPER_H
#define UBICD_X509HELPER_H


#include <ossl_typ.h>
#include <vector>

class X509Helper {
public:
    static std::vector<unsigned char> certToVector(X509* x509);
    static X509* vectorToCert(std::vector<unsigned char> certVector);
};


#endif //UBICD_X509HELPER_H
