
#ifndef UBICD_DEACTIVATECERTIFICATESCRIPT_H
#define UBICD_DEACTIVATECERTIFICATESCRIPT_H

#include "../Serialization/serialize.h"

#define TYPE_CSCA 0
#define TYPE_DSC 1

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

#endif
