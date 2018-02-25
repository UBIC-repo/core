#include <openssl/ossl_typ.h>
#include <vector>

#ifndef NTPESK_NTPRSKSIGNATUREREQUESTOBJECT_H
#define NTPESK_NTPRSKSIGNATUREREQUESTOBJECT_H

#endif //NTPESK_NTPRSKSIGNATUREREQUESTOBJECT_H

class NtpRskSignatureRequestObject {
private:
    const BIGNUM* e;
    const BIGNUM* n;
    BIGNUM* signature;
    BIGNUM* m;
    BIGNUM* paddedM;
    BIGNUM* nm;
    RSA* rsa;
public:
    const BIGNUM *getE() const {
        return this->e;
    }

    void setE(const BIGNUM *e) {
        this->e = e;
    }

    const BIGNUM *getN() const {
        return this->n;
    }

    void setN(const BIGNUM *n) {
        this->n = n;
    }

    BIGNUM *getSignature() const {
        return this->signature;
    }

    void setSignature(BIGNUM *signature) {
        this->signature = signature;
    }

    BIGNUM *getPaddedM() {
        return paddedM;
    }

    void setPaddedM(BIGNUM *paddedM) {
        this->paddedM = paddedM;
    }

    BIGNUM *getM() const {
        return this->m;
    }

    void setM(BIGNUM *m) {
        this->m = m;
    }

    BIGNUM *getNm() const {
        return this->nm;
    }

    void setNm(BIGNUM *nm) {
        this->nm = nm;
    }

    RSA *getRsa() {
        return rsa;
    }

    void setRsa(RSA *rsa) {
        this->rsa = rsa;
    }
};
