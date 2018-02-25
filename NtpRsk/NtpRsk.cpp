#include <openssl/bn.h>
#include "NtpRsk.h"
#include <openssl/rand.h>
#include <iostream>

/**
 * A is signature, X is the signed message hash
 * A^e = X
 *
 * e is the RSA exponent, typically 2^16 + 1
 *
 * The proof is d where 1 < d < e (typically 2^16)
 *
 * r is a random number, then:
 *
 * (A^d *r)^e = X^d * (r^e) mod n
 *    t                 T
 *
 *
 * (A^d1 *r)^e = X^d1 * (r^e) mod n
 * (A^d2 *r)^e = X^d2 * (r^e) mod n
 * (A^d3 *r)^e = X^d3 * (r^e) mod n
 * (A^d4 *r)^e = X^d4 * (r^e) mod n
 * (A^d5 *r)^e = X^d5 * (r^e) mod n
 *
 * what is published is T = (r^e)
 * t1 = (A^d1 *r)
 * t2 = (A^d2 *r)
 * t3 = (A^d3 *r)
 * t4 = (A^d4 *r)
 * t5 = (A^d5 *r)
 *
 */

NtpRskSignatureVerificationObject* NtpRsk::signWithNtpRsk(NtpRskSignatureRequestObject *ntpRskSignatureRequestObject) {

    NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = new NtpRskSignatureVerificationObject();

    const BIGNUM* n = ntpRskSignatureRequestObject->getN();
    const BIGNUM* e = ntpRskSignatureRequestObject->getE();
    BIGNUM* e2 = BN_new();
    BIGNUM* sub = BN_new();
    BIGNUM* add = BN_new();
    BN_dec2bn(&add, "2");
    BN_dec2bn(&sub, "4");
    BN_sub(e2, e, sub);
    BIGNUM* signature = ntpRskSignatureRequestObject->getSignature();
    BIGNUM* nm = ntpRskSignatureRequestObject->getNm();

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* r = randomBignum(n);
    BIGNUM* d = BN_new();
    BN_mod(d, nm, e2, ctx);
    BN_add(d, d, add);

    BIGNUM* t1 = BN_new();
    BIGNUM* T = BN_new();
    BIGNUM* salt = BN_new();

    std::cout << "d1 : " << BN_bn2dec(d) << std::endl;
    std::cout << "e : " << BN_bn2dec(e) << std::endl;
    std::cout << "n : " << BN_bn2dec(n) << std::endl;

    // T = r^v
    BN_mod_exp(T, r, e, n, ctx);
    ntpRskSignatureVerificationObject->setT(T);
    std::cout << "T : " << BN_bn2dec(T) << std::endl;

    // t1 =  (A^d *r)
    BN_mod_exp(t1, signature, d, n, ctx);
    BN_mod_mul(t1, t1, r, n, ctx);
    ntpRskSignatureVerificationObject->setT1(t1);

    // t2 =  (A^d *r)
    BIGNUM* t2 = BN_new();
    BIGNUM* XT = BN_new();
    BN_mod_exp(XT, t1, e, n, ctx);
    BN_dec2bn(&salt, "1618446177786864861468428776289946168463");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t2, signature, d, n, ctx);
    BN_mod_mul(t2, t2, r, n, ctx);
    ntpRskSignatureVerificationObject->setT2(t2);

    // t3 =  (A^d *r)
    BIGNUM* t3 = BN_new();
    BN_mod_exp(XT, t2, e, n, ctx);
    BN_dec2bn(&salt, "2468284666624768462658468131846646451821");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t3, signature, d, n, ctx);
    BN_mod_mul(t3, t3, r, n, ctx);
    ntpRskSignatureVerificationObject->setT3(t3);

    // t4 =  (A^d *r)
    BIGNUM* t4 = BN_new();
    BN_mod_exp(XT, t3, e, n, ctx);
    BN_dec2bn(&salt, "386846284626847646244761844687764462164");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t4, signature, d, n, ctx);
    BN_mod_mul(t4, t4, r, n, ctx);
    ntpRskSignatureVerificationObject->setT4(t4);

    // t5 =  (A^d *r)
    BIGNUM* t5 = BN_new();
    BN_mod_exp(XT, t4, e, n, ctx);
    BN_dec2bn(&salt, "456156843515512741515122247552415322464");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t5, signature, d, n, ctx);
    BN_mod_mul(t5, t5, r, n, ctx);
    ntpRskSignatureVerificationObject->setT5(t5);

    ntpRskSignatureVerificationObject->setPaddedM(ntpRskSignatureRequestObject->getPaddedM());
    ntpRskSignatureVerificationObject->setM(ntpRskSignatureRequestObject->getM());
    ntpRskSignatureVerificationObject->setNm(ntpRskSignatureRequestObject->getNm());
    ntpRskSignatureVerificationObject->setE(ntpRskSignatureRequestObject->getE());
    ntpRskSignatureVerificationObject->setN(ntpRskSignatureRequestObject->getN());


    return ntpRskSignatureVerificationObject;
}

bool NtpRsk::verifyNtpRsk(NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject) {

    BIGNUM* T = ntpRskSignatureVerificationObject->getT();
    BIGNUM* t1 = ntpRskSignatureVerificationObject->getT1();
    BIGNUM* t2 = ntpRskSignatureVerificationObject->getT2();
    BIGNUM* t3 = ntpRskSignatureVerificationObject->getT3();
    BIGNUM* t4 = ntpRskSignatureVerificationObject->getT4();
    BIGNUM* t5 = ntpRskSignatureVerificationObject->getT5();
    const BIGNUM* e = ntpRskSignatureVerificationObject->getE();
    BIGNUM* e2 = BN_new();
    BIGNUM* sub = BN_new();
    BIGNUM* add = BN_new();
    BN_dec2bn(&add, "2");
    BN_dec2bn(&sub, "4");
    BN_sub(e2, e, sub);
    const BIGNUM* n = ntpRskSignatureVerificationObject->getN();

    BIGNUM* m = ntpRskSignatureVerificationObject->getPaddedM();
    BIGNUM* nm = ntpRskSignatureVerificationObject->getNm();

    BN_CTX *ctx = BN_CTX_new();

    // verify t^v = X^d * T mod n
    BIGNUM* XT = BN_new();
    BIGNUM* salt = BN_new();
    BIGNUM* d = BN_new();
    BN_mod(d, nm, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t1, t1, e, n, ctx);

    BN_mod_exp(XT, m, d, n, ctx);
    BN_mod_mul(XT, XT, T, n, ctx);

    if(BN_cmp(XT, t1) != 0) {
        std::cout << "d1 : " << BN_bn2dec(d) << std::endl;
        std::cout << "e1 : " << BN_bn2dec(e) << std::endl;
        std::cout << "n1 : " << BN_bn2dec(n) << std::endl;
        std::cout << "T1 : " << BN_bn2dec(T) << std::endl;
        std::cout << "BN_cmp(XT, t1) failed" << std::endl;
        std::cout << "XT " << BN_bn2dec(XT) <<  std::endl;
        std::cout << "t1 " << BN_bn2dec(t1) << std::endl;
        return false;
    }

    // verify t^v = X^d * T mod n
    BN_dec2bn(&salt, "1618446177786864861468428776289946168463");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t2, t2, e, n, ctx);

    BN_mod_exp(XT, m, d, n, ctx);
    BN_mod_mul(XT, XT, T, n, ctx);

    if(BN_cmp(XT, t2) != 0) {
        std::cout << "BN_cmp(XT, t2) failed";
        return false;
    }

    // verify t^v = X^d * T mod n
    BN_dec2bn(&salt, "2468284666624768462658468131846646451821");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t3, t3, e, n, ctx);

    BN_mod_exp(XT, m, d, n, ctx);
    BN_mod_mul(XT, XT, T, n, ctx);

    if(BN_cmp(XT, t3) != 0) {
        std::cout << "BN_cmp(XT, t3) failed" << std::endl;
        return false;
    }

    // verify t^v = X^d * T mod n
    BN_dec2bn(&salt, "386846284626847646244761844687764462164");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t4, t4, e, n, ctx);

    BN_mod_exp(XT, m, d, n, ctx);
    BN_mod_mul(XT, XT, T, n, ctx);

    if(BN_cmp(XT, t4) != 0) {
        std::cout << "BN_cmp(XT, t4) failed" << std::endl;
        return false;
    }

    // verify t^v = X^d * T mod n
    BN_dec2bn(&salt, "456156843515512741515122247552415322464");
    BN_add(XT, XT, salt);
    BN_mod(d, XT, e2, ctx);
    BN_add(d, d, add);
    BN_mod_exp(t5, t5, e, n, ctx);

    BN_mod_exp(XT, m, d, n, ctx);
    BN_mod_mul(XT, XT, T, n, ctx);

    if(BN_cmp(XT, t5) != 0) {
        std::cout << "BN_cmp(XT, t5) failed" << std::endl;
        return false;
    }

    return true;
}

BIGNUM* NtpRsk::randomBignum(const BIGNUM* maxSize) {
    int byteLength = BN_num_bytes(maxSize);
    unsigned char buf[byteLength];
    RAND_bytes(buf, byteLength);

    return BN_bin2bn(buf, byteLength, NULL);
}
