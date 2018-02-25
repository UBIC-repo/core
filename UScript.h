
#ifndef TX_USCRIPT_H
#define TX_USCRIPT_H

#include <cstdint>

#define TYPE_CSCA 0
#define TYPE_DSC 1

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

#endif //TX_USCRIPT_H
