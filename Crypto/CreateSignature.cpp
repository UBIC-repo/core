#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "CreateSignature.h"
#include "../Tools/Log.h"
#include "../Wallet.h"

bool CreateSignature::sign(EVP_PKEY* key, const unsigned char* message, size_t messageLength, unsigned char* signature, size_t* signatureLength) {
    EVP_MD_CTX* signCTX = EVP_MD_CTX_create();

    if (EVP_DigestSignInit(signCTX,NULL, EVP_sha256(), NULL,key)<=0) {
        return false;
    }
    if (EVP_DigestSignUpdate(signCTX, message, messageLength) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(signCTX, NULL, signatureLength) <=0) {
        return false;
    }

    if (EVP_DigestSignFinal(signCTX, signature, signatureLength) <= 0) {
        return false;
    }

    return true;
}

std::vector<unsigned char> CreateSignature::sign(EVP_PKEY* key, std::vector<unsigned char> message) {
    unsigned char signature[256];
    size_t signatureLength;
    if(CreateSignature::sign(key, message.data(), message.size(), signature, &signatureLength)) {
        return std::vector<unsigned char> (signature, signature + signatureLength);
    }

    return std::vector<unsigned char>();
}

std::vector<unsigned char> CreateSignature::sign(std::vector<unsigned char> privateKey, std::vector<unsigned char> message) {

    BIGNUM* keyBn = BN_bin2bn(privateKey.data(), (int)privateKey.size(), NULL);
    EC_KEY* ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, Wallet::getDefaultEcGroup());
    EC_KEY_set_private_key(ecKey, keyBn);

    EVP_PKEY* key = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(key, ecKey);

    return CreateSignature::sign(key, message);
}
