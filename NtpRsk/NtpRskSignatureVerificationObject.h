#include <vector>
#include "../Crypto/ECCtools.h"
#include "../serialize.h"

#ifndef NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H
#define NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H

#endif //NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H

class NtpRskSignatureVerificationObject {
private:
    uint8_t version = 2;
    const BIGNUM* e;
    const BIGNUM* n;
    BIGNUM* T;
    BIGNUM* t1;
    BIGNUM* t2;
    BIGNUM* t3;
    BIGNUM* t4;
    BIGNUM* t5;
    BIGNUM* m;
    BIGNUM* paddedM;
    BIGNUM* nm;
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

    BIGNUM *getT() const {
        return this->T;
    }

    void setT(BIGNUM *T) {
        this->T = T;
    }

    BIGNUM *getT1() const {
        return this->t1;
    }

    void setT1(BIGNUM *t1) {
        this->t1 = t1;
    }

    BIGNUM *getT2() const {
        return this->t2;
    }

    void setT2(BIGNUM *t2) {
        this->t2 = t2;
    }

    BIGNUM *getT3() const {
        return t3;
    }

    void setT3(BIGNUM *t3) {
        this->t3 = t3;
    }

    BIGNUM *getT4() const {
        return this->t4;
    }

    void setT4(BIGNUM *t4) {
        this->t4 = t4;
    }

    BIGNUM *getT5() const {
        return this->t5;
    }

    void setT5(BIGNUM *t5) {
        this->t5 = t5;
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

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<unsigned char> TVector, t1Vector, t2Vector, t3Vector, t4Vector, t5Vector, mVector, paddedMVector, nmVector;
        if (std::is_same<Operation, CSerActionSerialize>::value) {
            TVector = ECCtools::bnToVector(T);
            t1Vector = ECCtools::bnToVector(t1);
            t2Vector = ECCtools::bnToVector(t2);
            t3Vector = ECCtools::bnToVector(t3);
            t4Vector = ECCtools::bnToVector(t4);
            t5Vector = ECCtools::bnToVector(t5);
            mVector = ECCtools::bnToVector(m);
            paddedMVector = ECCtools::bnToVector(paddedM);
            nmVector = ECCtools::bnToVector(nm);
        }

        READWRITE(version);
        READWRITE(TVector);
        READWRITE(t1Vector);
        READWRITE(t2Vector);
        READWRITE(t3Vector);
        READWRITE(t4Vector);
        READWRITE(t5Vector);
        READWRITE(mVector);
        READWRITE(paddedMVector);
        READWRITE(nmVector);

        if (std::is_same<Operation, CSerActionUnserialize>::value) {
            this->T = ECCtools::vectorToBn(TVector);
            this->t1 = ECCtools::vectorToBn(t1Vector);
            this->t2 = ECCtools::vectorToBn(t2Vector);
            this->t3 = ECCtools::vectorToBn(t3Vector);
            this->t4 = ECCtools::vectorToBn(t4Vector);
            this->t5 = ECCtools::vectorToBn(t5Vector);
            this->m = ECCtools::vectorToBn(mVector);
            this->paddedM = ECCtools::vectorToBn(paddedMVector);
            this->nm = ECCtools::vectorToBn(nmVector);
        }
    }
};