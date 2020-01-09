
#include <string.h>
#include <openssl/x509.h>
#include "X509Helper.h"

std::vector<unsigned char> X509Helper::certToVector(X509* x509){
    BIO *mem = BIO_new(BIO_s_mem());
    i2d_X509_bio(mem, x509);
    char* x509Buffer;
    long x509BufferLength = BIO_get_mem_data(mem, &x509Buffer);

    char* x509BufferCopy = (char*)malloc(x509BufferLength);
    memcpy(x509BufferCopy, x509Buffer, x509BufferLength);
    BIO_set_close(mem, BIO_CLOSE);
    BIO_free(mem);

    return std::vector<unsigned char>(x509BufferCopy, x509BufferCopy + x509BufferLength);
}

X509* X509Helper::vectorToCert(std::vector<unsigned char> certVector) {
    BIO *certbio = BIO_new_mem_buf(certVector.data(),
                                   (int) certVector.size());
    X509 *x509 = d2i_X509_bio(certbio, NULL);
    return x509;
}
