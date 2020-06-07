#include <openssl/bn.h>
#include "NtpRsk.h"
#include "../Tools/Hexdump.h"
#include "../Crypto/Sha256.h"
#include "../Tools/VectorTool.h"
#include <openssl/rand.h>
#include <iostream>

/**
 * Based on https://crypto.stackexchange.com/questions/81094/proving-the-knowlege-of-e-th-root-in-an-non-interactive-way
 * Prover part
 */
NtpRskSignatureVerificationObject* NtpRsk::signWithNtpRsk(NtpRskSignatureRequestObject *ntpRskSignatureRequestObject) {

    NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject = new NtpRskSignatureVerificationObject();
    const uint8_t version = ntpRskSignatureRequestObject->getVersion();
    const BIGNUM *n = ntpRskSignatureRequestObject->getN();
    const BIGNUM *e = ntpRskSignatureRequestObject->getE();
    BIGNUM *signature = ntpRskSignatureRequestObject->getSignature();
    BN_CTX *ctx = BN_CTX_new();

    if(version == 6) {

        // Step 1.

        BIGNUM *r1 = randomBignum(n);
        BIGNUM *r2 = randomBignum(n);
        BIGNUM *r3 = randomBignum(n);
        BIGNUM *r4 = randomBignum(n);
        BIGNUM *r5 = randomBignum(n);
        BIGNUM *r6 = randomBignum(n);
        BIGNUM *r7 = randomBignum(n);
        BIGNUM *r8 = randomBignum(n);

        // T1 = r1^e
        BIGNUM *T1 = BN_new();
        BN_mod_exp(T1, r1, e, n, ctx);

        // T2 = r2^e
        BIGNUM *T2 = BN_new();
        BN_mod_exp(T2, r2, e, n, ctx);

        // T1 = r3^e
        BIGNUM *T3 = BN_new();
        BN_mod_exp(T3, r3, e, n, ctx);

        // T1 = r4^e
        BIGNUM *T4 = BN_new();
        BN_mod_exp(T4, r4, e, n, ctx);

        // T1 = r5^e
        BIGNUM *T5 = BN_new();
        BN_mod_exp(T5, r5, e, n, ctx);

        // T1 = r6^e
        BIGNUM *T6 = BN_new();
        BN_mod_exp(T6, r6, e, n, ctx);

        // T1 = r7^e
        BIGNUM *T7 = BN_new();
        BN_mod_exp(T7, r7, e, n, ctx);

        // T8 = r8^e
        BIGNUM *T8 = BN_new();
        BN_mod_exp(T8, r8, e, n, ctx);

        //Step 2.
        std::vector<unsigned char> toHash = std::vector<unsigned char>();
        toHash = VectorTool::concatCharVector(BN_bn2hex(T1), "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T2));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T3));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T4));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T5));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T6));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T7));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T8));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, Hexdump::vectorToHexString(
                ntpRskSignatureRequestObject->getNm()
                                  ).c_str()
        );

        std::vector<unsigned char> randomOracleHash = Sha256::sha256(toHash);

        // Step 3.

        std::string hashString = Hexdump::vectorToHexString(randomOracleHash);

        BIGNUM *d1 = BN_new();
        BIGNUM *d2 = BN_new();
        BIGNUM *d3 = BN_new();
        BIGNUM *d4 = BN_new();
        BIGNUM *d5 = BN_new();
        BIGNUM *d6 = BN_new();
        BIGNUM *d7 = BN_new();
        BIGNUM *d8 = BN_new();

        // generate d1..d8 by using the 128 leading bits of the hash
        BN_hex2bn(&d1, hashString.substr(0, 4).c_str());
        BN_hex2bn(&d2, hashString.substr(4, 4).c_str());
        BN_hex2bn(&d3, hashString.substr(8, 4).c_str());
        BN_hex2bn(&d4, hashString.substr(12, 4).c_str());
        BN_hex2bn(&d5, hashString.substr(16, 4).c_str());
        BN_hex2bn(&d6, hashString.substr(20, 4).c_str());
        BN_hex2bn(&d7, hashString.substr(24, 4).c_str());
        BN_hex2bn(&d8, hashString.substr(28, 4).c_str());

        // verify all d numbers are in the range 2 < d < 65537
        // if this not the case we have to retry

        BIGNUM *bn3 = BN_new();
        BN_hex2bn(&bn3, "03");
        if(BN_cmp(d1, bn3) < 0
           || BN_cmp(d2, bn3) < 0
           || BN_cmp(d3, bn3) < 0
           || BN_cmp(d4, bn3) < 0
           || BN_cmp(d5, bn3) < 0
           || BN_cmp(d6, bn3) < 0
           || BN_cmp(d7, bn3) < 0
           || BN_cmp(d8, bn3) < 0
                ) {
            return NtpRsk::signWithNtpRsk(ntpRskSignatureRequestObject); // try again
        }

        //@TODO

        BIGNUM *t1 = BN_new();
        BIGNUM *t2 = BN_new();
        BIGNUM *t3 = BN_new();
        BIGNUM *t4 = BN_new();
        BIGNUM *t5 = BN_new();
        BIGNUM *t6 = BN_new();
        BIGNUM *t7 = BN_new();
        BIGNUM *t8 = BN_new();

        // calculate t1 = (u^d1)*r1
        BN_mod_exp(t1, signature, d1, n, ctx);
        BN_mod_mul(t1, t1, r1, n, ctx);

        // calculate t2 = (u^d2)*r2
        BN_mod_exp(t2, signature, d2, n, ctx);
        BN_mod_mul(t2, t2, r2, n, ctx);

        // calculate t3 = (u^d3)*r3
        BN_mod_exp(t3, signature, d3, n, ctx);
        BN_mod_mul(t3, t3, r3, n, ctx);

        // calculate t4 = (u^d4)*r4
        BN_mod_exp(t4, signature, d4, n, ctx);
        BN_mod_mul(t4, t4, r4, n, ctx);

        // calculate t5 = (u^d5)*r5
        BN_mod_exp(t5, signature, d5, n, ctx);
        BN_mod_mul(t5, t5, r5, n, ctx);

        // calculate t6 = (u^d6)*r6
        BN_mod_exp(t6, signature, d6, n, ctx);
        BN_mod_mul(t6, t6, r6, n, ctx);

        // calculate t7 = (u^d7)*r7
        BN_mod_exp(t7, signature, d7, n, ctx);
        BN_mod_mul(t7, t7, r7, n, ctx);

        // calculate t8 = (u^d8)*r8
        BN_mod_exp(t8, signature, d8, n, ctx);
        BN_mod_mul(t8, t8, r8, n, ctx);

        //step 4. (publish)

        ntpRskSignatureVerificationObject->setT1(t1);
        ntpRskSignatureVerificationObject->setT2(t2);
        ntpRskSignatureVerificationObject->setT3(t3);
        ntpRskSignatureVerificationObject->setT4(t4);
        ntpRskSignatureVerificationObject->setT5(t5);
        ntpRskSignatureVerificationObject->setT6(t6);
        ntpRskSignatureVerificationObject->setT7(t7);
        ntpRskSignatureVerificationObject->setT8(t8);

        ntpRskSignatureVerificationObject->setRandomOracleHash(randomOracleHash);
        ntpRskSignatureVerificationObject->setPaddedM(ntpRskSignatureRequestObject->getPaddedM());
        ntpRskSignatureVerificationObject->setM(ntpRskSignatureRequestObject->getM());
        ntpRskSignatureVerificationObject->setE(ntpRskSignatureRequestObject->getE());
        ntpRskSignatureVerificationObject->setN(ntpRskSignatureRequestObject->getN());
        ntpRskSignatureVerificationObject->setMdAlg(ntpRskSignatureRequestObject->getMdAlg());
        ntpRskSignatureVerificationObject->setSignedPayload(ntpRskSignatureRequestObject->getSignedPayload());

        return ntpRskSignatureVerificationObject;
    }

    return nullptr;
}

/**
 * Based on https://crypto.stackexchange.com/questions/81094/proving-the-knowlege-of-e-th-root-in-an-non-interactive-way
 * verifier part
 */
bool NtpRsk::verifyNtpRsk(NtpRskSignatureVerificationObject *ntpRskSignatureVerificationObject) {

    uint8_t version = ntpRskSignatureVerificationObject->getVersion();
    const BIGNUM *e = ntpRskSignatureVerificationObject->getE();
    const BIGNUM *n = ntpRskSignatureVerificationObject->getN();
    BIGNUM *m = ntpRskSignatureVerificationObject->getPaddedM();
    BN_CTX *ctx = BN_CTX_new();

    if(version == 6) {
        BIGNUM *t1 = ntpRskSignatureVerificationObject->getT1();
        BIGNUM *t2 = ntpRskSignatureVerificationObject->getT2();
        BIGNUM *t3 = ntpRskSignatureVerificationObject->getT3();
        BIGNUM *t4 = ntpRskSignatureVerificationObject->getT4();
        BIGNUM *t5 = ntpRskSignatureVerificationObject->getT5();
        BIGNUM *t6 = ntpRskSignatureVerificationObject->getT6();
        BIGNUM *t7 = ntpRskSignatureVerificationObject->getT7();
        BIGNUM *t8 = ntpRskSignatureVerificationObject->getT8();

        // Step 1.
        std::string hashString = Hexdump::vectorToHexString(ntpRskSignatureVerificationObject->getRandomOracleHash());

        BIGNUM *d1 = BN_new();
        BIGNUM *d2 = BN_new();
        BIGNUM *d3 = BN_new();
        BIGNUM *d4 = BN_new();
        BIGNUM *d5 = BN_new();
        BIGNUM *d6 = BN_new();
        BIGNUM *d7 = BN_new();
        BIGNUM *d8 = BN_new();

        // generate d1..d8 by using the 128 leading bits of the hash
        BN_hex2bn(&d1, hashString.substr(0, 4).c_str());
        BN_hex2bn(&d2, hashString.substr(4, 4).c_str());
        BN_hex2bn(&d3, hashString.substr(8, 4).c_str());
        BN_hex2bn(&d4, hashString.substr(12, 4).c_str());
        BN_hex2bn(&d5, hashString.substr(16, 4).c_str());
        BN_hex2bn(&d6, hashString.substr(20, 4).c_str());
        BN_hex2bn(&d7, hashString.substr(24, 4).c_str());
        BN_hex2bn(&d8, hashString.substr(28, 4).c_str());

        // verify all d numbers are in the range 2 < d < 65537
        // if this not the case the proof is invalid

        BIGNUM *bn3 = BN_new();
        BN_hex2bn(&bn3, "03");
        if(BN_cmp(d1, bn3) < 0
           || BN_cmp(d2, bn3) < 0
           || BN_cmp(d3, bn3) < 0
           || BN_cmp(d4, bn3) < 0
           || BN_cmp(d5, bn3) < 0
           || BN_cmp(d6, bn3) < 0
           || BN_cmp(d7, bn3) < 0
           || BN_cmp(d8, bn3) < 0
                ) {
            return false;
        }

        BIGNUM *T1 = BN_new();
        BIGNUM *T2 = BN_new();
        BIGNUM *T3 = BN_new();
        BIGNUM *T4 = BN_new();
        BIGNUM *T5 = BN_new();
        BIGNUM *T6 = BN_new();
        BIGNUM *T7 = BN_new();
        BIGNUM *T8 = BN_new();

        BIGNUM *te1 = BN_new();
        BIGNUM *te2 = BN_new();
        BIGNUM *te3 = BN_new();
        BIGNUM *te4 = BN_new();
        BIGNUM *te5 = BN_new();
        BIGNUM *te6 = BN_new();
        BIGNUM *te7 = BN_new();
        BIGNUM *te8 = BN_new();

        BIGNUM *md1 = BN_new();
        BIGNUM *md2 = BN_new();
        BIGNUM *md3 = BN_new();
        BIGNUM *md4 = BN_new();
        BIGNUM *md5 = BN_new();
        BIGNUM *md6 = BN_new();
        BIGNUM *md7 = BN_new();
        BIGNUM *md8 = BN_new();

        BN_mod_exp(te1, t1, e, n, ctx);
        BN_mod_exp(te2, t2, e, n, ctx);
        BN_mod_exp(te3, t3, e, n, ctx);
        BN_mod_exp(te4, t4, e, n, ctx);
        BN_mod_exp(te5, t5, e, n, ctx);
        BN_mod_exp(te6, t6, e, n, ctx);
        BN_mod_exp(te7, t7, e, n, ctx);
        BN_mod_exp(te8, t8, e, n, ctx);

        BN_mod_inverse(m, m, n, ctx); // m becomes it's inverse

        BN_mod_exp(md1, m, d1, n, ctx);
        BN_mod_exp(md2, m, d2, n, ctx);
        BN_mod_exp(md3, m, d3, n, ctx);
        BN_mod_exp(md4, m, d4, n, ctx);
        BN_mod_exp(md5, m, d5, n, ctx);
        BN_mod_exp(md6, m, d6, n, ctx);
        BN_mod_exp(md7, m, d7, n, ctx);
        BN_mod_exp(md8, m, d8, n, ctx);

        BN_mod_mul(T1, te1, md1, n, ctx);
        BN_mod_mul(T2, te2, md2, n, ctx);
        BN_mod_mul(T3, te3, md3, n, ctx);
        BN_mod_mul(T4, te4, md4, n, ctx);
        BN_mod_mul(T5, te5, md5, n, ctx);
        BN_mod_mul(T6, te6, md6, n, ctx);
        BN_mod_mul(T7, te7, md7, n, ctx);
        BN_mod_mul(T8, te8, md8, n, ctx);

        // Step 2.

        std::vector<unsigned char> toHash = std::vector<unsigned char>();
        toHash = VectorTool::concatCharVector(BN_bn2hex(T1), "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T2));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T3));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T4));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T5));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T6));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T7));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, BN_bn2hex(T8));
        toHash = VectorTool::concatCharVector(toHash, "|");
        toHash = VectorTool::concatCharVector(toHash, Hexdump::vectorToHexString(
                ntpRskSignatureVerificationObject->getNmVector()
                                  ).c_str()
        );

        std::vector<unsigned char> randomOracleHash = Sha256::sha256(toHash);

        return randomOracleHash == ntpRskSignatureVerificationObject->getRandomOracleHash();

    } else if(version == 2 || version == 4) { // depreciated
        BIGNUM *T = ntpRskSignatureVerificationObject->getT();
        BIGNUM *t1 = ntpRskSignatureVerificationObject->getT1();
        BIGNUM *t2 = ntpRskSignatureVerificationObject->getT2();
        BIGNUM *t3 = ntpRskSignatureVerificationObject->getT3();
        BIGNUM *t4 = ntpRskSignatureVerificationObject->getT4();
        BIGNUM *t5 = ntpRskSignatureVerificationObject->getT5();
        BIGNUM *e2 = BN_new();
        BIGNUM *sub = BN_new();
        BIGNUM *add = BN_new();
        BN_dec2bn(&add, "2");
        BN_dec2bn(&sub, "4");
        BN_sub(e2, e, sub);

        BIGNUM *nm = ntpRskSignatureVerificationObject->getNm();

        // verify t^v = X^d * T mod n (t1)
        BIGNUM *XT = BN_new();
        BIGNUM *salt = BN_new();
        BIGNUM *d = BN_new();
        BN_mod(d, nm, e2, ctx);
        BN_add(d, d, add);
        BN_mod_exp(t1, t1, e, n, ctx);

        BN_mod_exp(XT, m, d, n, ctx);
        BN_mod_mul(XT, XT, T, n, ctx);

        if (BN_cmp(XT, t1) != 0) {
            std::cout << "d1 : " << BN_bn2dec(d) << std::endl;
            std::cout << "e1 : " << BN_bn2dec(e) << std::endl;
            std::cout << "n1 : " << BN_bn2dec(n) << std::endl;
            std::cout << "T1 : " << BN_bn2dec(T) << std::endl;
            std::cout << "BN_cmp(XT, t1) failed" << std::endl;
            std::cout << "XT " << BN_bn2dec(XT) << std::endl;
            std::cout << "t1 " << BN_bn2dec(t1) << std::endl;
            BN_CTX_free(ctx);
            return false;
        }

        // verify t^v = X^d * T mod n (t2)
        BN_dec2bn(&salt, "1618446177786864861468428776289946168463");
        if (version >= 6) {
            BN_add(salt, salt, nm);
        }
        BN_add(XT, XT, salt);
        BN_mod(d, XT, e2, ctx);
        BN_add(d, d, add);
        BN_mod_exp(t2, t2, e, n, ctx);

        BN_mod_exp(XT, m, d, n, ctx);
        BN_mod_mul(XT, XT, T, n, ctx);

        if (BN_cmp(XT, t2) != 0) {
            std::cout << "BN_cmp(XT, t2) failed";
            BN_CTX_free(ctx);
            return false;
        }

        // verify t^v = X^d * T mod n (t3)
        BN_dec2bn(&salt, "2468284666624768462658468131846646451821");
        if (version >= 6) {
            BN_add(salt, salt, nm);
        }
        BN_add(XT, XT, salt);
        BN_mod(d, XT, e2, ctx);
        BN_add(d, d, add);
        BN_mod_exp(t3, t3, e, n, ctx);

        BN_mod_exp(XT, m, d, n, ctx);
        BN_mod_mul(XT, XT, T, n, ctx);

        if (BN_cmp(XT, t3) != 0) {
            std::cout << "BN_cmp(XT, t3) failed" << std::endl;
            BN_CTX_free(ctx);
            return false;
        }

        // verify t^v = X^d * T mod n (t4)
        BN_dec2bn(&salt, "386846284626847646244761844687764462164");
        if (version >= 6) {
            BN_add(salt, salt, nm);
        }
        BN_add(XT, XT, salt);
        BN_mod(d, XT, e2, ctx);
        BN_add(d, d, add);
        BN_mod_exp(t4, t4, e, n, ctx);

        BN_mod_exp(XT, m, d, n, ctx);
        BN_mod_mul(XT, XT, T, n, ctx);

        if (BN_cmp(XT, t4) != 0) {
            std::cout << "BN_cmp(XT, t4) failed" << std::endl;
            BN_CTX_free(ctx);
            BN_free(XT);
            BN_free(m);
            BN_free(nm);
            BN_free(salt);
            BN_free(d);
            BN_free(e2);
            BN_free(sub);
            BN_free(add);
            return false;
        }

        // verify t^v = X^d * T mod n (t5)
        BN_dec2bn(&salt, "456156843515512741515122247552415322464");
        if (version >= 6) {
            BN_add(salt, salt, nm);
        }
        BN_add(XT, XT, salt);
        BN_mod(d, XT, e2, ctx);
        BN_add(d, d, add);
        BN_mod_exp(t5, t5, e, n, ctx);

        BN_mod_exp(XT, m, d, n, ctx);
        BN_mod_mul(XT, XT, T, n, ctx);

        if (BN_cmp(XT, t5) != 0) {
            std::cout << "BN_cmp(XT, t5) failed" << std::endl;
            BN_CTX_free(ctx);
            BN_free(XT);
            BN_free(m);
            BN_free(nm);
            BN_free(salt);
            BN_free(d);
            BN_free(e2);
            BN_free(sub);
            BN_free(add);
            return false;
        }

        BN_CTX_free(ctx);
        BN_free(XT);
        BN_free(m);
        BN_free(nm);
        BN_free(salt);
        BN_free(d);
        BN_free(e2);
        BN_free(sub);
        BN_free(add);
        return true;
    }

    return false;
}

BIGNUM* NtpRsk::randomBignum(const BIGNUM* maxSize) {
    int byteLength = BN_num_bytes(maxSize);
    unsigned char buf[byteLength];
    RAND_bytes(buf, byteLength);

    return BN_bin2bn(buf, byteLength, NULL);
}
