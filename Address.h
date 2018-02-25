
#ifndef TX_ADDRESS_H
#define TX_ADDRESS_H

#include <cstdint>
#include "UAmount.h"
#include "UScript.h"
#include "streams.h"
#include "Crypto/Hash160.h"
#include "ChainParams.h"

class Address {
protected:
    UScript script;
public:
    UScript getScript();
    void setScript(UScript script);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(script);
    }
};


class AddressForStore : public Address {
private:
    std::vector<unsigned char> dscCertificate;
    uint32_t DSCLinkedAtHeight = 0;
    UAmount UBIdebit;
    UAmount amount;
    uint32_t nonce = 0;
public:

    UAmount getAmount() {
        return amount;
    }

    void setAmount(UAmount amount) {
        AddressForStore::amount = amount;
    }

    uint32_t getNonce() {
        return nonce;
    }

    void setNonce(uint32_t nonce) {
        AddressForStore::nonce = nonce;
    }

    std::vector<unsigned char> getDscCertificate() {
        return dscCertificate;
    }

    void setDscCertificate(std::vector<unsigned char> dscCertificate) {
        AddressForStore::dscCertificate = dscCertificate;
    }

    uint32_t getDSCLinkedAtHeight() {
        return DSCLinkedAtHeight;
    }

    void setDSCLinkedAtHeight(uint32_t DSCLinkedAtHeight) {
        AddressForStore::DSCLinkedAtHeight = DSCLinkedAtHeight;
    }

    UAmount getUBIdebit() {
        return UBIdebit;
    }

    void setUBIdebit(UAmount UBIdebit) {
        AddressForStore::UBIdebit = UBIdebit;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nonce);
        READWRITE(script);
        READWRITE(dscCertificate);
        READWRITE(DSCLinkedAtHeight);
        READWRITE(UBIdebit);
        READWRITE(amount);
    }
};

#endif //TX_ADDRESS_H
