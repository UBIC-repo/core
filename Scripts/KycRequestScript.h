
#ifndef TX_KYCREQUESTSCRIPT_H
#define TX_KYCREQUESTSCRIPT_H

#include <cstdint>
#include "../Transaction/Transaction.h"

#define KYC_MODE_ANONYMOUS 0
#define KYC_MODE_DG1 1
#define KYC_MODE_DG1_AND_DG2 2

struct KycRequestScript {
    uint8_t mode;
    uint16_t mdAlg;
    Transaction transaction; // if the passport is not yet registered we provide the register passport transaction
    std::vector<unsigned char> passportHash; // if the passport is already registered on the blockchain the register passport transaction is not needed
    std::vector<unsigned char> challenge;
    std::vector<unsigned char> challengeSignature;
    std::vector<unsigned char> signedPayload;
    std::vector<unsigned char> ldsPayload;
    std::vector<unsigned char> publicKey; // of the transaction address
    std::vector<unsigned char> dg1; // written information
    std::vector<unsigned char> dg2; // facial image

    uint8_t getMode() const {
        return mode;
    }

    void setMode(uint8_t mode) {
        KycRequestScript::mode = mode;
    }

    uint16_t getMdAlg() const {
        return mdAlg;
    }

    void setMdAlg(uint16_t mdAlg) {
        KycRequestScript::mdAlg = mdAlg;
    }

    const Transaction &getTransaction() const {
        return transaction;
    }

    void setTransaction(const Transaction &transaction) {
        KycRequestScript::transaction = transaction;
    }

    const vector<unsigned char> &getPassportHash() const {
        return passportHash;
    }

    void setPassportHash(const vector<unsigned char> &passportHash) {
        KycRequestScript::passportHash = passportHash;
    }

    const std::vector<unsigned char> &getChallenge() const {
        return challenge;
    }

    void setChallenge(const std::vector<unsigned char> &challenge) {
        KycRequestScript::challenge = challenge;
    }

    const std::vector<unsigned char> &getChallengeSignature() const {
        return challengeSignature;
    }

    void setChallengeSignature(const std::vector<unsigned char> &challengeSignature) {
        KycRequestScript::challengeSignature = challengeSignature;
    }

    const std::vector<unsigned char> &getSignedPayload() const {
        return signedPayload;
    }

    void setSignedPayload(const std::vector<unsigned char> &signedPayload) {
        KycRequestScript::signedPayload = signedPayload;
    }

    const std::vector<unsigned char> &getLdsPayload() const {
        return ldsPayload;
    }

    void setLdsPayload(const std::vector<unsigned char> &ldsPayload) {
        KycRequestScript::ldsPayload = ldsPayload;
    }

    const vector<unsigned char> &getPublicKey() const {
        return publicKey;
    }

    void setPublicKey(const vector<unsigned char> &publicKey) {
        KycRequestScript::publicKey = publicKey;
    }

    const std::vector<unsigned char> &getDg1() const {
        return dg1;
    }

    void setDg1(const std::vector<unsigned char> &dg1) {
        KycRequestScript::dg1 = dg1;
    }

    const std::vector<unsigned char> &getDg2() const {
        return dg2;
    }

    void setDg2(const std::vector<unsigned char> &dg2) {
        KycRequestScript::dg2 = dg2;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mode);
        READWRITE(mdAlg);
        READWRITE(transaction);
        READWRITE(passportHash);
        READWRITE(challenge);
        READWRITE(challengeSignature);
        READWRITE(signedPayload);
        READWRITE(ldsPayload);
        READWRITE(publicKey);
        READWRITE(dg1);
        READWRITE(dg2);
    }

};

#endif
