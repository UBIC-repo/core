

#ifndef UBICD_ADDCERTIFICATESCRIPT_H
#define UBICD_ADDCERTIFICATESCRIPT_H

#include <cstdint>
#include "../serialize.h"

#define TYPE_CSCA 0
#define TYPE_DSC 1

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

#endif