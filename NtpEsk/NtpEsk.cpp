#include <openssl/rand.h>
#include <iostream>
#include "NtpEsk.h"
#include "../Tools/Log.h"

using namespace std;

bool NtpEsk::verifyNtpEsk(NtpEskSignatureVerificationObject *ntpEskSignatureVerificationObject) {

    if(
            ntpEskSignatureVerificationObject->getPubKey() == NULL
            || ntpEskSignatureVerificationObject->getCurveParams() == NULL
            || ntpEskSignatureVerificationObject->getR() == NULL
            || ntpEskSignatureVerificationObject->getRp() == NULL
            || ntpEskSignatureVerificationObject->getSp() == NULL
            || ntpEskSignatureVerificationObject->getMessageHash().size() < 2
            || ntpEskSignatureVerificationObject->getNewMessageHash().size() < 2
            ) {
        Log(LOG_LEVEL_ERROR) << "ntpEskSignatureVerificationObject invalid";
        return false;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *spInverse = BN_new();
    BIGNUM *n = BN_new();
    uint8_t hashLengthM = (uint8_t) ntpEskSignatureVerificationObject->getMessageHash().size();
    uint8_t hashLengthNm = (uint8_t) ntpEskSignatureVerificationObject->getNewMessageHash().size();
    const BIGNUM *sp = ntpEskSignatureVerificationObject->getSp();
    const BIGNUM *rp = ntpEskSignatureVerificationObject->getRp();
    const EC_POINT *R = ntpEskSignatureVerificationObject->getR();
    BIGNUM *r = BN_new();
    const EC_GROUP *curveParams = ntpEskSignatureVerificationObject->getCurveParams();
    const EC_POINT *pubKey = ntpEskSignatureVerificationObject->getPubKey();
    const EC_POINT *G = EC_GROUP_get0_generator(curveParams);
    EC_POINT_get_affine_coordinates_GFp(curveParams, R, r, NULL, NULL);
    EC_GROUP_get_order(curveParams, n, ctx);

    BIGNUM *m = BN_bin2bn(ntpEskSignatureVerificationObject->getMessageHash().data(), hashLengthM, NULL);
    BIGNUM *nm = BN_bin2bn(ntpEskSignatureVerificationObject->getNewMessageHash().data(), hashLengthNm, NULL);

    unsigned char minHash[1] = {'\x01'};
    if(BN_cmp(nm, BN_bin2bn(minHash, 1, NULL)) != 1) {
        Log(LOG_LEVEL_ERROR) << "new hash is smaller or equal to 1";
        BN_CTX_free(ctx);
        return false;
    }

    if(BN_cmp(m, BN_bin2bn(minHash, 1, NULL)) != 1) {
        Log(LOG_LEVEL_ERROR) << "hash smaller or equal to 1";
        BN_CTX_free(ctx);
        return false;
    }

    // Verification step 1.
    //
    // Qa′ = m ∗ G + r ∗ Qa
    //

    EC_POINT *mG = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, mG, n, G, m, NULL);

    EC_POINT *rQa = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, rQa, n, pubKey, r, NULL);

    EC_POINT *Qap = EC_POINT_new(curveParams);
    EC_POINT_add(curveParams, Qap, mG, rQa, NULL);

    // Verification step 2.
    //
    // R′ = (s'^−1 * m′) ∗ R + (s'^−1 * r′) ∗ Qa′
    //
    BN_mod_inverse(spInverse, sp, n, ctx);

    BIGNUM *siprp = BN_new();
    BN_mod_mul(siprp, spInverse, rp, n, ctx);

    EC_POINT *siprpQap = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, siprpQap, n, Qap, siprp, NULL);

    BIGNUM *sipmp = BN_new();
    BN_mod_mul(sipmp, spInverse, nm, n, ctx);

    EC_POINT *sipmpR = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, sipmpR, n, R, sipmp, NULL);

    EC_POINT *calculatedRp = EC_POINT_new(curveParams);
    EC_POINT_add(curveParams, calculatedRp, siprpQap, sipmpR, NULL);

    BIGNUM *calculatedrp = BN_new();
    EC_POINT_get_affine_coordinates_GFp(curveParams, calculatedRp, calculatedrp, NULL, NULL);

    BN_CTX_free(ctx);

    if(BN_cmp(calculatedrp, rp) == 0) {
        return true;
    } else {
        return false;
    }

}

NtpEskSignatureVerificationObject *NtpEsk::signWithNtpEsk(NtpEskSignatureRequestObject *ntpEskSignatureRequestObject) {

    if(
        ntpEskSignatureRequestObject->getPubKey() == NULL
       || ntpEskSignatureRequestObject->getCurveParams() == NULL
       || ntpEskSignatureRequestObject->getR() == NULL
       || ntpEskSignatureRequestObject->getS() == NULL
       || ntpEskSignatureRequestObject->getMessageHash().size() == 0
       || ntpEskSignatureRequestObject->getNewMessageHash().size() == 0
    ) {
        return NULL;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    uint8_t hashLengthM = (uint8_t) ntpEskSignatureRequestObject->getMessageHash().size();
    uint8_t hashLengthNm = (uint8_t) ntpEskSignatureRequestObject->getNewMessageHash().size();
    const BIGNUM *s = ntpEskSignatureRequestObject->getS();
    const BIGNUM *r = ntpEskSignatureRequestObject->getR();
    const EC_GROUP *curveParams = ntpEskSignatureRequestObject->getCurveParams();
    EC_GROUP_get_order(curveParams, n, ctx);
    const EC_POINT *pubKey = ntpEskSignatureRequestObject->getPubKey();
    const EC_POINT *G = EC_GROUP_get0_generator(curveParams);

    BIGNUM *m = BN_bin2bn(ntpEskSignatureRequestObject->getMessageHash().data(), hashLengthM, NULL);
    BIGNUM *nm = BN_bin2bn(ntpEskSignatureRequestObject->getNewMessageHash().data(), hashLengthNm, NULL);

    // Step 1.
    // calculate R and verify that R(x) = r
    // R = (s^−1 * m)∗G + (s^−1 * r)∗Qa
    BIGNUM *sInverse = BN_mod_inverse(NULL, s, n, ctx);

    BIGNUM *s1 = BN_new();
    BN_mod_mul(s1, sInverse, m, n, ctx);
    EC_POINT *sp1 = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, sp1, NULL, G, s1, NULL);

    BIGNUM *s2 = BN_new();
    BN_mod_mul(s2, sInverse, r, n, ctx);
    EC_POINT *sp2 = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, sp2, NULL, pubKey, s2, NULL);

    EC_POINT *R = EC_POINT_new(curveParams);
    EC_POINT_add(curveParams, R, sp1, sp2, NULL);

    BIGNUM *calculatedr = BN_new();
    EC_POINT_get_affine_coordinates_GFp(curveParams, R, calculatedr, NULL, NULL);

    if(BN_cmp(calculatedr, r) != 0) {
        return NULL;
    }

    // Step 2.
    // Calculate Qa′
    // Qa′ = s ∗ R
    EC_POINT *Qap = EC_POINT_new(curveParams);
    EC_POINT_mul(curveParams, Qap, n, R, s, NULL);

    // Step 3.
    // Calculate R′
    // R′ = k′ ∗ R
    // where k' is a nonce you generated
    EC_POINT *Rp = EC_POINT_new(curveParams);
    BIGNUM *kp = randomBignum(n);
    EC_POINT_mul(curveParams, Rp, n, R, kp, NULL);

    // Step 4.
    // Calculate s′
    // s′ = k′−1(m′+r′∗s)
    // where m′ is the hash of a message you want to sign with your derived private key s.
    BIGNUM *kpInverse = BN_mod_inverse(NULL, kp, n, ctx);
    BIGNUM *rp = BN_new();
    EC_POINT_get_affine_coordinates_GFp(curveParams, Rp, rp, NULL, NULL);

    BIGNUM *rs = BN_new();
    BN_mod_mul(rs, rp, s, n, ctx);

    BIGNUM *mrs = BN_new();
    BN_mod_add(mrs, nm, rs, n, ctx);

    BIGNUM *sp = BN_new();
    BN_mod_mul(sp, kpInverse, mrs, n, ctx);

    NtpEskSignatureVerificationObject *response = new NtpEskSignatureVerificationObject();

    response->setCurveParams(ntpEskSignatureRequestObject->getCurveParams());
    response->setMessageHash(ntpEskSignatureRequestObject->getMessageHash());
    response->setNewMessageHash(ntpEskSignatureRequestObject->getNewMessageHash());
    response->setPubKey(ntpEskSignatureRequestObject->getPubKey());
    response->setR(R);
    response->setRp(rp);
    response->setSp(sp);
    response->setMdAlg(ntpEskSignatureRequestObject->getMdAlg());
    response->setSignedPayload(ntpEskSignatureRequestObject->getSignedPayload());

    return response;
}

BIGNUM* NtpEsk::randomBignum(BIGNUM* maxSize) {
    int byteLength = BN_num_bytes(maxSize);
    unsigned char buf[byteLength];
    RAND_bytes(buf, byteLength);

    return BN_bin2bn(buf, byteLength, NULL);
}
