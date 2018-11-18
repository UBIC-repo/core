
#ifndef NTPESK_NTPESKSIGNATUREVERIFICATIONOBJECT_H
#define NTPESK_NTPESKSIGNATUREVERIFICATIONOBJECT_H

#include <openssl/evp.h>
#include "../serialize.h"
#include "../Crypto/ECCtools.h"

class NtpEskSignatureVerificationObject {
private:
    uint8_t version = 1;
    const EC_GROUP *curveParams;
    const EC_POINT *pubKey;
    const EC_POINT *R;
    const BIGNUM *rp;
    const BIGNUM *sp;
    std::vector<unsigned char> messageHash;
    std::vector<unsigned char> newMessageHash;
    uint16_t mdAlg;
    std::vector<unsigned char> signedPayload;
public:
    const EC_POINT *getPubKey() const {
        return this->pubKey;
    }

    void setPubKey(const EC_POINT *pubKey) {
        this->pubKey = pubKey;
    }

    const EC_GROUP *getCurveParams() const {
        return this->curveParams;
    }

    void setCurveParams(const EC_GROUP *curveParams) {
        this->curveParams = curveParams;
    }

    const EC_POINT *getR() const {
        return this->R;
    }

    void setR(const EC_POINT *R) {
        this->R = R;
    }

    const BIGNUM *getRp() const {
        return this->rp;
    }

    void setRp(const BIGNUM *rp) {
        this->rp = rp;
    }

    const BIGNUM *getSp() const {
        return this->sp;
    }

    void setSp(const BIGNUM *sp) {
        this->sp = sp;
    }

    const std::vector<unsigned char> &getMessageHash() const {
        return this->messageHash;
    }

    void setMessageHash(const std::vector<unsigned char> &messageHash) {
        this->messageHash = messageHash;
    }

    const std::vector<unsigned char> &getNewMessageHash() const {
        return this->newMessageHash;
    }

    void setNewMessageHash(const std::vector<unsigned char> &newMessageHash) {
        this->newMessageHash = newMessageHash;
    }

    uint8_t getVersion() const {
        return version;
    }

    void setVersion(uint8_t version) {
        NtpEskSignatureVerificationObject::version = version;
    }

    uint16_t getMdAlg() const {
        return mdAlg;
    }

    void setMdAlg(uint16_t mdAlg) {
        NtpEskSignatureVerificationObject::mdAlg = mdAlg;
    }

    const std::vector<unsigned char> &getSignedPayload() {
        return signedPayload;
    }

    void setSignedPayload(const std::vector<unsigned char> &signedPayload) {
        NtpEskSignatureVerificationObject::signedPayload = signedPayload;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<unsigned char> rVector, rpVector, spVector;
        if (std::is_same<Operation, CSerActionSerialize>::value) {
            rVector = ECCtools::ecPointToVector(curveParams, R);
            rpVector = ECCtools::bnToVector(rp);
            spVector = ECCtools::bnToVector(sp);
        }

        READWRITE(version);
        READWRITE(messageHash);
        READWRITE(rVector);
        READWRITE(rpVector);
        READWRITE(spVector);

        if(version >= 3) {
            READWRITE(mdAlg);
            READWRITE(signedPayload);
        }

        if (std::is_same<Operation, CSerActionUnserialize>::value) {
            R = ECCtools::vectorToEcPoint(curveParams, rVector);
            rp = ECCtools::vectorToBn(rpVector);
            sp = ECCtools::vectorToBn(spVector);
        }
    }
};
#endif //NTPESK_NTPESKSIGNATUREVERIFICATIONOBJECT_H
