

#ifndef UBICD_PKHINSCRIPT_H
#define UBICD_PKHINSCRIPT_H

#include "../Serialization/serialize.h"

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

#endif