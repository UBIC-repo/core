#include <openssl/objects.h>
#include <openssl/evp.h>
#include <iostream>
#include <openssl/x509.h>
#include "PKCS7Parser.h"

void PKCS7Parser::pkcs7MsgSigDigest(PKCS7* p7, unsigned char *dig, unsigned int *diglen) {
    PKCS7_SIGNER_INFO *si;
    STACK_OF(PKCS7_SIGNER_INFO) *siStack;
    siStack = PKCS7_get_signer_info(p7);
    si = sk_PKCS7_SIGNER_INFO_value(siStack, 0);
    ASN1_OCTET_STRING *os;

    STACK_OF(X509_ATTRIBUTE) *sk;
    unsigned char *abuf = NULL;
    int alen;
    EVP_MD_CTX *mdc_tmp;

    sk = si->auth_attr;
    alen = ASN1_item_i2d((ASN1_VALUE *)sk, &abuf,
                         ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
    int md_type = OBJ_obj2nid(si->digest_alg->algorithm);

    mdc_tmp = EVP_MD_CTX_new();
    EVP_VerifyInit_ex(mdc_tmp, EVP_get_digestbynid(md_type), NULL);
    EVP_VerifyUpdate(mdc_tmp, abuf, (size_t)alen);
    EVP_DigestFinal_ex(mdc_tmp, dig, diglen);
}

PKCS7Parser::PKCS7Parser(char* sod, size_t sodSize) {
    BIO *bSod = BIO_new_mem_buf(sod, sodSize);

    this->p7 = d2i_PKCS7_bio( bSod, &this->p7 );
}

X509* PKCS7Parser::getDscCertificate() {
    if(this->p7 == NULL) {
        return nullptr;
    }

    X509* dscCertificate;
    STACK_OF(X509) *dsCerts = this->p7->d.sign->cert;

    if (sk_X509_num(dsCerts) > 0) {
        dscCertificate = sk_X509_value(dsCerts, 0);
    }

    return dscCertificate;
}

bool PKCS7Parser::hasError() {
    if(this->p7 == NULL) {
        return true;
    }

    return false;
}

bool PKCS7Parser::isECDSA() {
    if(getDscCertificate() == nullptr) {
        return false;
    }

    int signatureNid = X509_get_signature_nid(getDscCertificate());

    if (signatureNid == NID_ecdsa_with_SHA224 ||
        signatureNid == NID_ecdsa_with_SHA256 ||
        signatureNid == NID_ecdsa_with_SHA384 ||
        signatureNid == NID_ecdsa_with_SHA512) {
        return true;
    }

    return false;
}

bool PKCS7Parser::isRSA() {
    int signatureNid = X509_get_signature_nid(getDscCertificate());

    if (signatureNid == NID_sha224WithRSAEncryption ||
        signatureNid == NID_sha256WithRSAEncryption ||
        signatureNid == NID_sha384WithRSAEncryption ||
        signatureNid == NID_sha512WithRSAEncryption) {
        return true;
    }

    return false;
}

NtpRskSignatureRequestObject* PKCS7Parser::getNtpRsk() {
    if(!this->isRSA()) {
        return nullptr;
    }
    EVP_PKEY* pkey;
    pkey = X509_get0_pubkey(getDscCertificate());
    BN_CTX *ctx = BN_CTX_new();
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    const BIGNUM* n = BN_new();
    const BIGNUM* e = BN_new();
    RSA_get0_key(rsa, &n, &e, nullptr);

    STACK_OF(PKCS7_SIGNER_INFO) *siStack;
    PKCS7_SIGNER_INFO *si;

    siStack = PKCS7_get_signer_info(p7);
    si = sk_PKCS7_SIGNER_INFO_value(siStack, 0);

    std::vector<unsigned char> sigVector = std::vector<unsigned char>(si->enc_digest->data, si->enc_digest->data + si->enc_digest->length);

    unsigned char md_dat[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    pkcs7MsgSigDigest(p7, md_dat, &md_len);

    BIGNUM* signature = ECCtools::vectorToBn(sigVector);
    NtpRskSignatureRequestObject* ntpRskSignatureRequestObject = new NtpRskSignatureRequestObject();
    ntpRskSignatureRequestObject->setN(n);
    ntpRskSignatureRequestObject->setE(e);
    ntpRskSignatureRequestObject->setSignature(signature);

    ntpRskSignatureRequestObject->setM(ECCtools::vectorToBn(std::vector<unsigned char>(md_dat, md_dat +md_len)));
    BIGNUM *m = BN_new();
    BN_mod_exp(m, signature, e , n, ctx);
    ntpRskSignatureRequestObject->setPaddedM(m);
    ntpRskSignatureRequestObject->setRsa(rsa);

    return ntpRskSignatureRequestObject;
}

NtpEskSignatureRequestObject* PKCS7Parser::getNtpEsk() {
    if(!this->isECDSA()) {
        return nullptr;
    }
    EVP_PKEY* pkey;
    pkey = X509_get0_pubkey(getDscCertificate());

    STACK_OF(PKCS7_SIGNER_INFO) *siStack;
    PKCS7_SIGNER_INFO *si;

    siStack = PKCS7_get_signer_info(p7);
    si = sk_PKCS7_SIGNER_INFO_value(siStack, 0);


    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_POINT* ecPoint = EC_KEY_get0_public_key(ecKey);
    const unsigned char* cSig = si->enc_digest->data;
    ECDSA_SIG* ecSig = d2i_ECDSA_SIG(NULL, &cSig, (size_t)si->enc_digest->length);

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(ecSig, &r, &s);

    unsigned char md_dat[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    pkcs7MsgSigDigest(p7, md_dat, &md_len);

    NtpEskSignatureRequestObject* ntpEskSignatureRequestObject = new NtpEskSignatureRequestObject();
    ntpEskSignatureRequestObject->setPubKey(ecPoint);
    ntpEskSignatureRequestObject->setCurveParams(EC_KEY_get0_group(ecKey));
    ntpEskSignatureRequestObject->setR(r);
    ntpEskSignatureRequestObject->setS(s);
    ntpEskSignatureRequestObject->setMessageHash(std::vector<unsigned char>(md_dat, md_dat +md_len));

    return ntpEskSignatureRequestObject;
}
