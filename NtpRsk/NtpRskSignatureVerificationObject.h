#include <vector>
#include "../Crypto/ECCtools.h"
#include "../Serialization/serialize.h"
#include "../Fixes.h"
#include <openssl/evp.h>

#ifndef NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H
#define NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H

#endif //NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H

class NtpRskSignatureVerificationObject {
private:
    uint8_t version = 6;
    const BIGNUM* e;
    const BIGNUM* n;
    BIGNUM* T; // depreciated in version 6
    BIGNUM* t1;
    BIGNUM* t2;
    BIGNUM* t3;
    BIGNUM* t4;
    BIGNUM* t5;
    BIGNUM* t6;
    BIGNUM* t7;
    BIGNUM* t8;
    BIGNUM* m;
    BIGNUM* paddedM;
    BIGNUM* nm;
    std::vector<unsigned char> randomOracleHash;
    uint16_t mdAlg;
    std::vector<unsigned char> signedPayload;
    std::vector<unsigned char> mVector;
    std::vector<unsigned char> nmVector;
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

    BIGNUM *getT6() const {
        return t6;
    }

    void setT6(BIGNUM *t6) {
        NtpRskSignatureVerificationObject::t6 = t6;
    }

    BIGNUM *getT7() const {
        return t7;
    }

    void setT7(BIGNUM *t7) {
        NtpRskSignatureVerificationObject::t7 = t7;
    }

    BIGNUM *getT8() const {
        return t8;
    }

    void setT8(BIGNUM *t8) {
        NtpRskSignatureVerificationObject::t8 = t8;
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

    const std::vector<unsigned char> &getRandomOracleHash() const {
        return randomOracleHash;
    }

    void setRandomOracleHash(const std::vector<unsigned char> &randomOracleHash) {
        NtpRskSignatureVerificationObject::randomOracleHash = randomOracleHash;
    }

    uint8_t getVersion() const {
        return version;
    }

    void setVersion(uint8_t version) {
        NtpRskSignatureVerificationObject::version = version;
    }

    uint16_t getMdAlg() const {
        return mdAlg;
    }

    void setMdAlg(uint16_t mdAlg) {
        NtpRskSignatureVerificationObject::mdAlg = mdAlg;
    }

    const std::vector<unsigned char> &getSignedPayload() const {
        return signedPayload;
    }

    void setSignedPayload(const std::vector<unsigned char> &signedPayload) {
        NtpRskSignatureVerificationObject::signedPayload = signedPayload;
    }

    const std::vector<unsigned char> &getMVector() const {
        return mVector;
    }

    void setMVector(const std::vector<unsigned char> &mVector) {
        NtpRskSignatureVerificationObject::mVector = mVector;
    }

    const std::vector<unsigned char> &getNmVector() const {
        return nmVector;
    }

    void setNmVector(const std::vector<unsigned char> &nmVector) {
        NtpRskSignatureVerificationObject::nmVector = nmVector;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<unsigned char> TVector, t1Vector, t2Vector, t3Vector, t4Vector, t5Vector, t6Vector, t7Vector, t8Vector, paddedMVector, nmVector;
        if (std::is_same<Operation, CSerActionSerialize>::value) {
            if (version < 6) {
                TVector = ECCtools::bnToVector(T); // depreciated in version 6
            }
            t1Vector = ECCtools::bnToVector(t1);
            t2Vector = ECCtools::bnToVector(t2);
            t3Vector = ECCtools::bnToVector(t3);
            t4Vector = ECCtools::bnToVector(t4);
            t5Vector = ECCtools::bnToVector(t5);
            t6Vector = ECCtools::bnToVector(t6);
            t7Vector = ECCtools::bnToVector(t7);
            t8Vector = ECCtools::bnToVector(t8);
            paddedMVector = ECCtools::bnToVector(paddedM);
            if (version < 6) {
                nmVector = ECCtools::bnToVector(nm);
            }
        }

        READWRITE(version);
        if (version < 6) {
            READWRITE(TVector); // depreciated in version 6
        }
        READWRITE(t1Vector);
        READWRITE(t2Vector);
        READWRITE(t3Vector);
        READWRITE(t4Vector);
        READWRITE(t5Vector);

        if (version >= 6) { // new in version 6
            READWRITE(t6Vector);
            READWRITE(t7Vector);
            READWRITE(t8Vector);
            READWRITE(randomOracleHash);
        }

        if (version < 6) {
            READWRITE(mVector); // depreciated in version 6
        }

        READWRITE(paddedMVector);
        if (version < 6) {
            READWRITE(nmVector); // depreciated in version 6
        }
        
        if(version >= 4) { // new in version 4
            READWRITE(mdAlg);
            READWRITE(signedPayload);

            // we calculate the the message Hash (m) from the payload

            unsigned char digest[128];
            unsigned int digestLength;
            EVP_MD_CTX *mdctx;
            mdctx = EVP_MD_CTX_create();

            EVP_DigestInit_ex(mdctx, EVP_get_digestbynid(
                    Fixes::fixWrongHashAlg(mVector, mdAlg)
                    ), NULL);
            EVP_DigestUpdate(mdctx, signedPayload.data(),
                             signedPayload.size());
            EVP_DigestFinal_ex(mdctx, digest, &digestLength);

            EVP_MD_CTX_destroy(mdctx);
            mVector = std::vector<unsigned char>(digest, digest + digestLength);
        }

        if (std::is_same<Operation, CSerActionUnserialize>::value) {
            if (version < 6) {
                this->T = ECCtools::vectorToBn(TVector);
            }
            this->t1 = ECCtools::vectorToBn(t1Vector);
            this->t2 = ECCtools::vectorToBn(t2Vector);
            this->t3 = ECCtools::vectorToBn(t3Vector);
            this->t4 = ECCtools::vectorToBn(t4Vector);
            this->t5 = ECCtools::vectorToBn(t5Vector);
            this->t6 = ECCtools::vectorToBn(t6Vector);
            this->t7 = ECCtools::vectorToBn(t7Vector);
            this->t8 = ECCtools::vectorToBn(t8Vector);
            this->m = ECCtools::vectorToBn(mVector);
            this->paddedM = ECCtools::vectorToBn(paddedMVector);
            this->nm = ECCtools::vectorToBn(nmVector);
        }
    }
};
