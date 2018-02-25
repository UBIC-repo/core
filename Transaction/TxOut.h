
#ifndef TX_TXOUT_H
#define TX_TXOUT_H


#include <cstdint>
#include "../UAmount.h"
#include "../UScript.h"

class TxOut {
private:
    UAmount amount;
    UScript script;
public:
    UAmount getAmount();
    void setAmount(UAmount &amount);
    UScript getScript();
    void setScript(UScript script);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(amount);
        READWRITE(script);
    }
};


#endif //TX_TXOUT_H
