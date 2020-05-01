
#ifndef TX_TXIN_H
#define TX_TXIN_H

#include <cstdint>
#include "../UAmount.h"
#include "../Scripts/UScript.h"

class TxIn {
private:
    UAmount amount;
    std::vector<unsigned char> inAddress;
    uint32_t nonce; // @TODO nonce should use a compact encoding!
    UScript script;
public:
    UAmount getAmount();
    void setAmount(const UAmount &amount);
    std::vector<unsigned char> getInAddress();
    void setInAddress(std::vector<unsigned char> inAddress);
    uint32_t getNonce();
    void setNonce(uint32_t nonce);
    UScript getScript();
    void setScript(UScript script);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(amount);
        READWRITE(inAddress);
        READWRITE(nonce);
        READWRITE(script);
    }
};


#endif //TX_TXIN_H
