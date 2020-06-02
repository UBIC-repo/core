

#ifndef UBICD_HELPER_H
#define UBICD_HELPER_H


#include <openssl/bio.h>
#include <openssl/err.h>
#include <string>

class Helper {
public:
    static std::string getOpenSSLError()
    {
        BIO *bio = BIO_new(BIO_s_mem());
        ERR_print_errors(bio);
        char *buf;
        size_t len = BIO_get_mem_data(bio, &buf);
        std::string ret(buf, len);
        BIO_free(bio);
        return ret;
    }
};


#endif //UBICD_HELPER_H
