#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <vector>

#ifndef NTPESK_NTPESKSIGNATUREREQUESTOBJECT_H
#define NTPESK_NTPESKSIGNATUREREQUESTOBJECT_H

class NtpEskSignatureRequestObject {
private:
    const EC_POINT *pubKey;
    const EC_GROUP *curveParams;
    const BIGNUM *r;
    const BIGNUM *s;
    std::vector<unsigned char> messageHash;
    std::vector<unsigned char> newMessageHash;
    uint16_t mdAlg;
    std::vector<unsigned char> signedPayload;
public:
    const EC_POINT* getPubKey() const {
        return pubKey;
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

    const BIGNUM *getR() const {
        return this->r;
    }

    void setR(const BIGNUM *r) {
        this->r = r;
    }

    const BIGNUM *getS() const {
        return this->s;
    }

    void setS(const BIGNUM *s) {
        this->s = s;
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

    uint16_t getMdAlg() const {
        return mdAlg;
    }

    void setMdAlg(uint16_t mdAlg) {
        NtpEskSignatureRequestObject::mdAlg = mdAlg;
    }

    const std::vector<unsigned char> &getSignedPayload() const {
        return signedPayload;
    }

    void setSignedPayload(const std::vector<unsigned char> &signedPayload) {
        NtpEskSignatureRequestObject::signedPayload = signedPayload;
    }
};

#endif //NTPESK_NTPESKSIGNATUREREQUESTOBJECT_H
