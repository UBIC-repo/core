
#ifndef TX_USCRIPT_H
#define TX_USCRIPT_H

#include <cstdint>

#define TYPE_CSCA 0
#define TYPE_DSC 1

#define KYC_MODE_ANONYMOUS 0
#define KYC_MODE_DG1 1
#define KYC_MODE_DG1_AND_DG2 2

struct UScript {
    // 0x01 link to an existing txoutput
    // 0x02 for PKH
    // 0x03 CSCA/DSC add Certificate
    // 0x04 CSCA/DSC remove Certificate
    // 0x05 Vote
    // 0x06 reserved
    // 0x07 reserved
    // 0x08 reserved
    // 0x09 register passport, only exists as input
    // 0x10 Script Language 1 will be implemented in the future
    // 0x11 Script Language 2 might be implemented in the future
    // 0x12 Script Language 3 might be implemented in the future
    uint8_t scriptType;
    std::vector<unsigned char> script;

    uint8_t getScriptType() const {
        return scriptType;
    }

    void setScriptType(uint8_t scriptType) {
        UScript::scriptType = scriptType;
    }

    const std::vector<unsigned char> &getScript() const {
        return script;
    }

    void setScript(const std::vector<unsigned char> &script) {
        UScript::script = script;
    }

    void setScript(unsigned char* script, uint16_t scriptLength) {
        UScript::script = std::vector<unsigned char>(script, script + scriptLength);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(scriptType);
        READWRITE(script);
    }
};

struct AddCertificateScript {
    uint8_t version = 1;
    uint8_t type; // 0x00: csca, 0x01 dsc
    uint8_t currency;
    uint64_t expirationDate;
    std::vector<unsigned char> certificate;
    std::vector<unsigned char> rootSignature;

    bool isCSCA() {
        return type == TYPE_CSCA;
    }

    bool isDSC() {
        return type == TYPE_DSC;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(type);
        READWRITE(version);
        READWRITE(currency);
        READWRITE(expirationDate);
        READWRITE(certificate);
        READWRITE(rootSignature);
    }

};


struct DeactivateCertificateScript {
    uint8_t version = 1;
    uint8_t type; // 0x00: csca, 0x01 dsc
    uint32_t nonce;
    std::vector<unsigned char> certificateId;
    std::vector<unsigned char> rootCertSignature;

    bool isCSCA() {
        return type == TYPE_CSCA;
    }

    bool isDSC() {
        return type == TYPE_DSC;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(type);
        READWRITE(rootCertSignature);
    }
};

struct PkhInScript {
    uint8_t version = 1;
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> signature;

    uint8_t getVersion() {
        return version;
    }

    void setVersion(uint8_t version) {
        this->version = version;
    }

    std::vector<unsigned char> getPublicKey() {
        return publicKey;
    }

    void setPublicKey(const std::vector<unsigned char> publicKey) {
        this->publicKey = publicKey;
    }

    std::vector<unsigned char> getSignature() {
        return signature;
    }

    void setSignature(std::vector<unsigned char> signature) {
        this->signature = signature;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(publicKey);
        READWRITE(signature);
    }
};

struct NtpskAlreadyUsedScript {
    std::vector<unsigned char> address;
    std::vector<unsigned char> dscID;

    const std::vector<unsigned char> &getAddress() const {
        return address;
    }

    void setAddress(const std::vector<unsigned char> &address) {
        NtpskAlreadyUsedScript::address = address;
    }

    const std::vector<unsigned char> &getDscID() const {
        return dscID;
    }

    void setDscID(const std::vector<unsigned char> &dscID) {
        NtpskAlreadyUsedScript::dscID = dscID;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(address);
        READWRITE(dscID);
    }

};

struct KycRequestScript {
    uint8_t mode;
    std::vector<unsigned char> passportHash;
    std::vector<unsigned char> addressPublicKey;
    std::vector<unsigned char> challenge;
    std::vector<unsigned char> challengeSignature;
    std::vector<unsigned char> ldsHashes;
    std::vector<unsigned char> dg1; // written information
    std::vector<unsigned char> dg2; // facial image

    uint8_t getMode() const {
        return mode;
    }

    void setMode(uint8_t mode) {
        KycRequestScript::mode = mode;
    }

    const std::vector<unsigned char> &getPassportHash() const {
        return passportHash;
    }

    void setPassportHash(const std::vector<unsigned char> &passportHash) {
        KycRequestScript::passportHash = passportHash;
    }

    const std::vector<unsigned char> &getAddressPublicKey() const {
        return addressPublicKey;
    }

    void setAddressPublicKey(const std::vector<unsigned char> &addressPublicKey) {
        KycRequestScript::addressPublicKey = addressPublicKey;
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

    const std::vector<unsigned char> &getLdsHashes() const {
        return ldsHashes;
    }

    void setLdsHashes(const std::vector<unsigned char> &ldsHashes) {
        KycRequestScript::ldsHashes = ldsHashes;
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
        READWRITE(passportHash);
        READWRITE(addressPublicKey);
        READWRITE(challenge);
        READWRITE(challengeSignature);
        READWRITE(ldsHashes);
        READWRITE(dg1);
        READWRITE(dg2);
    }

};

struct ChangeCertificateCurrencyIdScript {
    uint8_t version = 1;
    uint32_t nonce;
    uint8_t from;
    uint8_t to;
    std::vector<unsigned char> dscID;

    uint8_t getVersion() const {
        return version;
    }

    void setVersion(uint8_t version) {
        ChangeCertificateCurrencyIdScript::version = version;
    }

    uint32_t getNonce() const {
        return nonce;
    }

    void setNonce(uint32_t nonce) {
        ChangeCertificateCurrencyIdScript::nonce = nonce;
    }

    uint8_t getFrom() const {
        return from;
    }

    void setFrom(uint8_t from) {
        ChangeCertificateCurrencyIdScript::from = from;
    }

    uint8_t getTo() const {
        return to;
    }

    void setTo(uint8_t to) {
        ChangeCertificateCurrencyIdScript::to = to;
    }

    const std::vector<unsigned char> &getDscID() const {
        return dscID;
    }

    void setDscID(const std::vector<unsigned char> &dscID) {
        ChangeCertificateCurrencyIdScript::dscID = dscID;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(nonce);
        READWRITE(from);
        READWRITE(to);
    }
};

#endif //TX_USCRIPT_H
